'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('root bundle promotion refuses mutable ancestors and symlinks', () => {
    const script = path.resolve(__dirname, '../scripts/install-provisioning-worker.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util, stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('installer', ${JSON.stringify(script)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
for unsafe in [SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
               SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=999),
               SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0)]:
    with patch.object(Path, 'lstat', return_value=unsafe):
        try: m.safe_target(Path('/usr/local/lib/test-worker'))
        except ValueError: pass
        else: raise AssertionError('unsafe ancestry accepted')
with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)):
    m.safe_target(Path('/usr/local/lib/test-worker'))
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});

test('source promotion rejects symlinks and unbounded files', () => {
    const script = path.resolve(__dirname, '../scripts/install-provisioning-worker.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util, tempfile
from pathlib import Path
spec = importlib.util.spec_from_file_location('installer', ${JSON.stringify(script)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source = root / 'source.py'; source.write_text('print(1)')
    link = root / 'link.py'; link.symlink_to(source)
    large = root / 'large.py'; large.write_bytes(b'x' * (512 * 1024 + 1))
    for unsafe in [link, large, root]:
        try: m.reviewed_source(unsafe)
        except ValueError: pass
        else: raise AssertionError('unsafe source accepted')
    assert m.reviewed_source(source) == b'print(1)'
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});

test('atomic promotion preserves existing content on a refused destination', () => {
    const script = path.resolve(__dirname, '../scripts/install-provisioning-worker.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util, tempfile
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('installer', ${JSON.stringify(script)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
    target = Path(directory) / 'worker.py'; target.write_bytes(b'previous')
    with patch.object(m, 'safe_target', side_effect=ValueError('unsafe')):
        try: m.atomic_install(target, b'replacement', 0o755)
        except ValueError: pass
        else: raise AssertionError('unsafe destination accepted')
    assert target.read_bytes() == b'previous'
    assert list(Path(directory).iterdir()) == [target]
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});

test('dry-run promotion validates every payload without commands or writes', () => {
    const script = path.resolve(__dirname, '../scripts/install-provisioning-worker.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('installer', ${JSON.stringify(script)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with patch.object(m, 'reviewed_source', return_value=b'# reviewed payload'), \\
     patch.object(m, 'safe_target'), \\
     patch.object(m, 'atomic_install') as write, \\
     patch.object(m.subprocess, 'run') as command:
    assert m.main([]) == 0
    assert not write.called
    assert not command.called
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});

test('bundle promotion creates a private rollback inventory before replacement', () => {
    const script = path.resolve(__dirname, '../scripts/install-provisioning-worker.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util, json, stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('installer', ${JSON.stringify(script)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
target = Path('/usr/local/lib/sokrat-tenant-provisioning/worker.py')
with patch.object(m, 'safe_target'), \\
     patch.object(Path, 'mkdir'), \\
     patch.object(Path, 'exists', return_value=True), \\
     patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755)), \\
     patch.object(m, 'reviewed_source', return_value=b'previous'), \\
     patch.object(m, 'atomic_install') as write, \\
     patch.object(m.subprocess, 'run') as command:
    m.promote([(target, b'replacement', 0o755)])
    calls = write.call_args_list
    assert len(calls) == 3
    assert calls[0].args[1] == b'previous'
    inventory = calls[1].args
    assert inventory[0].name == 'inventory.json' and inventory[2] == 0o600
    assert str(target) in json.loads(inventory[1])
    assert calls[2].args == (target, b'replacement', 0o755)
    assert command.call_args.args[0] == ['systemctl', 'daemon-reload']
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});
