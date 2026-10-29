#!/usr/bin/env python3
"""Systemctl compatibility shim for containerized Sokrat Tenant Provisioning.

Emulates systemctl lifecycle commands for tenant TURN relays (sokrat-tenant-turn@<slug>.service)
and standard service reload commands inside a Docker container.
"""
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

RUN_DIR = Path('/run/sokrat-turn')
RUN_DIR.mkdir(parents=True, exist_ok=True)
TENANT_SERVICE_PATTERN = re.compile(r'^sokrat-tenant-turn@([a-z0-9-]+)\.service$')


def get_pid_file(slug):
    return RUN_DIR / f"{slug}.pid"


def is_process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def get_tenant_pid(slug):
    pid_file = get_pid_file(slug)
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
        return pid if is_process_alive(pid) else None
    except (ValueError, OSError):
        return None


def start_tenant(slug):
    conf_file = Path(f"/etc/sokrat/turn/{slug}/turnserver.conf")
    if not conf_file.exists():
        sys.stderr.write(f"Config not found: {conf_file}\n")
        return 1

    existing_pid = get_tenant_pid(slug)
    if existing_pid:
        return 0  # Already running

    user = f"sokrat-turn-{slug}"
    cmd = ["/usr/bin/turnserver", "-c", str(conf_file), "--pidfile="]
    try:
        import pwd
        try:
            pw = pwd.getpwnam(user)
            uid, gid = pw.pw_uid, pw.pw_gid
        except KeyError:
            uid, gid = 0, 0

        def preexec():
            if uid != 0:
                os.setgid(gid)
                os.setuid(uid)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=preexec,
            start_new_session=True,
        )
        get_pid_file(slug).write_text(str(proc.pid))
        return 0
    except Exception as e:
        sys.stderr.write(f"Failed to start tenant {slug}: {e}\n")
        return 1


def stop_tenant(slug):
    pid = get_tenant_pid(slug)
    pid_file = get_pid_file(slug)
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    if pid_file.exists():
        try:
            pid_file.unlink()
        except OSError:
            pass
    return 0


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(0)

    action = args[0]

    if action == "daemon-reload":
        sys.exit(0)

    if action == "reload":
        unit = args[1] if len(args) > 1 else ""
        if unit == "nginx":
            res = subprocess.run(["nginx", "-s", "reload"])
            sys.exit(res.returncode)
        sys.exit(0)

    if action == "is-active":
        if len(args) < 2:
            print("inactive")
            sys.exit(3)
        unit = args[1]
        m = TENANT_SERVICE_PATTERN.match(unit)
        if m:
            slug = m.group(1)
            if get_tenant_pid(slug):
                print("active")
                sys.exit(0)
            else:
                print("inactive")
                sys.exit(3)
        print("active")
        sys.exit(0)

    if action in ("enable", "restart", "start"):
        target = args[-1]
        m = TENANT_SERVICE_PATTERN.match(target)
        if m:
            slug = m.group(1)
            if action == "restart":
                stop_tenant(slug)
            sys.exit(start_tenant(slug))
        sys.exit(0)

    if action in ("disable", "stop"):
        target = args[-1]
        m = TENANT_SERVICE_PATTERN.match(target)
        if m:
            slug = m.group(1)
            sys.exit(stop_tenant(slug))
        sys.exit(0)

    sys.exit(0)


if __name__ == '__main__':
    main()
