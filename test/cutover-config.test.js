'use strict';
const { test } = require('node:test');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('tenant nginx cutover is idempotent and refuses missing legacy routes', () => {
    execFileSync('python3', ['-c', `
import importlib.util
spec = importlib.util.spec_from_file_location('cutover', 'scripts/enable-tenant-routing.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sip = 'location = /ws { proxy_pass http://pbx.example:8088/ws; }'
push = 'server {\\n' + ''.join('    location = ' + p + ' {\\n        proxy_pass http://127.0.0.1:8095;\\n    }\\n' for p in ('/api/push/register-device', '/api/push/remove-device', '/api/mobile/ice')) + '    location / { return 404; }\\n}'
a, b = module.render(sip, push)
assert '9097/ws' in a and b.count('return 410') == 3
assert module.render(a, b) == (a, b)
for invalid in ('server {}', push.replace('/api/mobile/ice', '/wrong')):
    try:
        module.render(sip, invalid)
    except ValueError:
        pass
    else:
        raise AssertionError('Unsafe configuration accepted')
`], { cwd: path.resolve(__dirname, '..'), stdio: 'pipe' });
});
