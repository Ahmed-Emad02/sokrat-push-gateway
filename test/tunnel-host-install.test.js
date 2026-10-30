'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('host enrollment promotion is inert by default and refuses an active broker', () => {
    const script = path.resolve(__dirname,'../scripts/install-tunnel-enrollment.py');
    const output = execFileSync('python3',['-B','-c',`
import importlib.util,sys,subprocess
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('installer',${JSON.stringify(script)})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with patch.object(sys,'argv',['installer']),patch.object(subprocess,'run') as run:
 m.main();assert not run.called
with patch.object(sys,'argv',['installer','--apply']),patch('os.geteuid',return_value=0),patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
 try:m.main();raise AssertionError('active service was overwritten')
 except ValueError:pass
 assert run.call_count==1
print('ok')`],{encoding:'utf8',timeout:15000});
    assert.match(output,/Dry-run:/);
    assert.match(output,/ok\s*$/);
});
