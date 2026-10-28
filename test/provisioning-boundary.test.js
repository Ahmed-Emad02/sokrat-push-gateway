'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('bundle promotion neither enables the timer nor restarts call services', () => {
    const installer = fs.readFileSync(path.resolve(__dirname, '../scripts/install-provisioning-worker.py'), 'utf8');
    assert.match(installer, /\/usr\/local\/lib\/sokrat-tenant-provisioning/);
    assert.match(installer, /os\.fchown\(stream\.fileno\(\), 0, 0\)/);
    assert.match(installer, /compile\(payload/);
    assert.doesNotMatch(installer, /\['systemctl', '(?:enable|restart|reload)'/);
    assert.match(installer, /Timer is stopped/);
});
