'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { createControl } = require('../src/control');

test('Python broker and real Node bridge agree on stable registration and reject disabled retries', async () => {
    const root = await fsp.mkdtemp(path.join(os.tmpdir(),'sokrat-tunnel-bridge-'));
    const token = crypto.randomBytes(32).toString('base64url');
    const control = createControl({ filePath:path.join(root,'control.json'),
        credential:{configured:false,source:'fixture'}, loginFailureDelayMs:0 });
    await control.init();
    const app = express();
    app.use('/control',control.router);
    const server = await new Promise(resolve => {
        const s = app.listen(0,'127.0.0.1',() => resolve(s));
    });
    const original = fs.readFileSync;
    fs.readFileSync = function(file,...args) {
        if (file === '/etc/sokrat/gateway-tunnel-bridge.token') return token;
        return original.call(this,file,...args);
    };
    try {
        const python = `
import importlib.util
from unittest.mock import patch
from pathlib import Path
s=importlib.util.spec_from_file_location('broker','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
config={'controlPort':${server.address().port}}
entry={'pbxId':'pbx_0123456789abcdef','installationId':'a'*32,'ports':m.proxy_ports(3),'plan':{'pbxIp':'10.253.0.14'}}
with patch.object(Path,'read_text',return_value=${JSON.stringify(token)}):
 result=m.bridge(config,entry,'Integration fixture')
 assert result['success'] is True
 assert result['enabled'] is ${'EXPECTED_ENABLED'}
 assert result['approvalStatus']=='approved'
print('ok')`;
        const run = async enabled => {
            const { stdout } = await promisify(execFile)('python3',['-B','-c',python.replace('EXPECTED_ENABLED',enabled?'True':'False')],
                {cwd:path.resolve(__dirname,'../scripts'),timeout:15000});
            assert.equal(stdout.trim(),'ok');
        };
        await run(true);
        await run(true);
        assert.equal(control.store.listPbx().length,1);
        await control.store.updatePbx('pbx_0123456789abcdef',{enabled:false});
        await run(false);
        assert.equal(control.store.getPbx('pbx_0123456789abcdef').enabled,false);
    } finally {
        fs.readFileSync = original;
        control.close();
        await new Promise(resolve => server.close(resolve));
        await fsp.rm(root,{recursive:true,force:true});
    }
});
