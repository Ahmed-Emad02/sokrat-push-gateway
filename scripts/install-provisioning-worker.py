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
        print('Timer will remain disabled until explicitly enabled by the operator.')
        return 0
    if os.geteuid() != 0:
        raise ValueError('--apply requires root')
    # Do not replace code while a provisioning job may be running. Stop only
    # this dedicated worker/timer; never restart the call runtime or Asterisk.
    for unit in reversed(UNITS):
        loaded = subprocess.run(['systemctl', 'show', unit, '--property=LoadState', '--value'],
                                check=True, capture_output=True, text=True, timeout=30)
        if loaded.stdout.strip() != 'not-found':
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
    print('Installed root-owned provisioning bundle. Timer is stopped.')
    print('Prior files backed up in ' + str(backup))
    print('Configure authorized access before enabling sokrat-tenant-provisioning.timer.')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError):
        print('Provisioning bundle installation refused or failed; timer was not enabled.',
              file=sys.stderr)
        sys.exit(2)
