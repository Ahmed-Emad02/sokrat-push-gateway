'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('local firewall creates exact tenant gates, revokes them and propagates failures', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util,subprocess
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('firewall',${JSON.stringify(path.resolve(__dirname, '../docker/provisioning-firewall-local.py'))})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
commands=[]
def run(argv,check=True):
 commands.append((argv,check))
 return SimpleNamespace(returncode=1 if '-S' in argv or '-C' in argv else 0,stdout='')
with patch.object(m.shutil,'which',return_value='/usr/sbin/iptables'),patch.object(m,'run_cmd',side_effect=run):
 m.configure(3503,True)
 assert commands[-1][0][-5:]==['-R','SKGL3503','1','-j','ACCEPT']
 assert sum('-I' in a for a,c in commands)==2
 assert all('3503' in a or 'SKGL3503' in a for a,c in commands)
 assert not any('-F' in a or '-P' in a for a,c in commands)
 commands.clear();m.configure(3503,False)
 assert any(a[-5:]==['-R','SKGL3503','1','-j','DROP'] for a,c in commands)
 assert not any('ACCEPT' in a for a,c in commands)
with patch.object(m.shutil,'which',return_value=None):
 try:m.configure(3503,True);raise AssertionError('missing firewall accepted')
 except ValueError:pass
with patch.object(m.shutil,'which',return_value='/usr/sbin/iptables'),patch.object(m,'run_cmd',side_effect=subprocess.TimeoutExpired('iptables',15)):
 try:m.configure(3503,True);raise AssertionError('failure ignored')
 except subprocess.SubprocessError:pass
print('ok')`], { encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
});
