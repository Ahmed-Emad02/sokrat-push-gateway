'use strict';
const { test } = require('node:test');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('relay slugs fit Linux account limits and port allocations stay disjoint', () => {
    execFileSync('python3', ['-c', `
import importlib.util
s = importlib.util.spec_from_file_location('sync', 'scripts/sync-tenant-runtime.py')
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
taken = set()
for value in ('pbx_b02b63850dbb278c', 'pbx_' + 'a' * 60, 'PBX_' + 'a' * 60):
    slug = m.derive_slug(value, taken)
    taken.add(slug)
    assert len('sokrat-turn-' + slug) <= 31
    assert m.SLUG_RE.fullmatch(slug)
assert len(taken) == 3
assert m.MAX_SLOTS == 155
`], { cwd: path.resolve(__dirname, '..'), stdio: 'pipe' });
});
