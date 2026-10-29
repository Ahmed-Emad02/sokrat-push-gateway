#!/usr/bin/env python3
"""Install an operator-reviewed, immutable provisioning bundle. Dry-run by default.

Never point the root service at the web-service-owned application directory.
This installer is an explicit trust/promotion operation; it does not configure
customer SSH access, grant cloud permissions, or enable the timer implicitly.
"""
import argparse
import datetime
import hashlib
import json
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


BUNDLE = Path('/usr/local/lib/sokrat-tenant-provisioning')
FILES = (
    'reconcile-tenant-provisioning.py', 'sync-tenant-runtime.py',
    'provisioning-hook-ssh.py', 'provisioning-firewall-aws.py',
    'install-tenant-push-hook.py', 'pbx-tenant-push-hook.py',
    'provisioning-onboarding.py',
)
UNITS = ('sokrat-tenant-provisioning.service', 'sokrat-tenant-provisioning.timer',
         'sokrat-tenant-onboarding.service')
TIMER = 'sokrat-tenant-provisioning.timer'
ONBOARDING = 'sokrat-tenant-onboarding.service'


def safe_target(path):
    """Every existing ancestor must be root-owned and not mutable by the app."""
    for part in reversed([path, *path.parents]):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe installation destination')


def atomic_install(path, payload, mode):
    safe_target(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, 0)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def reviewed_source(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024:
        raise ValueError('source must be a bounded regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > 512 * 1024:
            raise ValueError('source changed while opening')
        payload = stream.read(512 * 1024 + 1)
    if len(payload) > 512 * 1024:
        raise ValueError('source is too large')
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    # Read all files before changing the host; operator is explicitly promoting
    # this reviewed source snapshot. No customer-controlled source filenames.
    installs = [(BUNDLE / name, reviewed_source(root / 'scripts' / name), 0o755)
                for name in FILES]
    installs += [(Path('/etc/systemd/system') / name,
                  reviewed_source(root / 'systemd' / name), 0o644) for name in UNITS]
    for destination, payload, _ in installs:
        if destination.suffix == '.py':
            compile(payload, str(destination), 'exec')
        safe_target(destination)
    if not args.apply:
        print('Dry-run: validated root bundle and systemd destinations; no writes.')
        print('Dry-run does not change unit states or enable the timer.')
        return 0
    if os.geteuid() != 0:
        raise ValueError('--apply requires root')
    # Snapshot all states before stopping anything. Never enable units as part of
    # promotion: only restore units that were already active after it succeeds.
    restore = []
    loaded_units = []
    for unit in (TIMER, UNITS[0], ONBOARDING):
        loaded = subprocess.run(['systemctl', 'show', unit, '--property=LoadState', '--value'],
                                check=True, capture_output=True, text=True, timeout=30)
        if loaded.stdout.strip() != 'not-found':
            loaded_units.append(unit)
            if unit in (TIMER, ONBOARDING):
                state = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState', '--value'],
                                       check=True, capture_output=True, text=True, timeout=30)
                if state.stdout.strip() not in ('active', 'inactive', 'failed'):
                    raise ValueError('unit state is changing; retry promotion')
                if state.stdout.strip() == 'active':
                    restore.append(unit)
    # Stop the timer first so it cannot start another job during promotion.
    # Never restart the call runtime or Asterisk.
    for unit in loaded_units:
        subprocess.run(['systemctl', 'stop', unit], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    # Refuse replacement if a manual invocation still holds the worker lock.
    lock_dir = Path('/run/sokrat-tenant-provisioning')
    safe_target(lock_dir)
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    safe_target(lock_dir / 'lock')
    lock_fd = os.open(lock_dir / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(lock_fd)
        raise ValueError('another provisioning invocation is running')
    # Hold the descriptor in a context so failed backup/promotion closes it too.
    with os.fdopen(lock_fd, 'r+b', closefd=True):
        promote(installs)
    # Do not restart the oneshot worker directly: its timer will run it normally.
    # A failure during promotion intentionally leaves stopped units stopped.
    for unit in reversed(restore):
        subprocess.run(['systemctl', 'start', unit], check=True, timeout=30)
    print('Restored previously active onboarding and timer units; no units enabled.')
    return 0


def promote(installs):
    backup = Path('/var/backups/sokrat-gateway') / (
        'provisioning-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    safe_target(backup)
    backup.mkdir(parents=True, mode=0o700)
    inventory = {}
    for destination, _, _ in installs:
        if destination.exists():
            prior = reviewed_source(destination)
            inventory[str(destination)] = hashlib.sha256(prior).hexdigest()
            atomic_install(backup / destination.name, prior,
                           stat.S_IMODE(destination.stat().st_mode))
    atomic_install(backup / 'inventory.json',
                   (json.dumps(inventory, indent=2, sort_keys=True) + '\n').encode(), 0o600)
    for destination, payload, mode in installs:
        atomic_install(destination, payload, mode)
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=30)
    print('Installed root-owned provisioning bundle.')
    print('Prior files backed up in ' + str(backup))
    print('Previously inactive units remain stopped; configure authorized access before enabling the timer.')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError):
        print('Provisioning bundle installation refused or failed; check timer and onboarding unit states.',
              file=sys.stderr)
        sys.exit(2)
