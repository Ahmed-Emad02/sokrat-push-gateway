#!/usr/bin/env python3
"""Reconcile operator-selected gateway UDP media ports with the host firewall.

Desired ports come only from enrolled installations whose persisted
``mediaTransport`` is an explicit direct/plain UDP endpoint. Legacy rows without
that field are never converted or opened. The installer's sanitized
``host-firewall.json`` is the manifest: it keeps unrelated/operator ports and
records which media ports are registry-derived. Reconcile is additive: it never
deletes a firewall rule, flushes a firewall, or rewrites unrelated manifest
fields. Closing a port remains an explicit operator action.
"""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MANIFEST = Path('/etc/sokrat/host-firewall.json')
REGISTRY = Path('/etc/sokrat/tunnel-enrollment/installations.json')
PORT_RE = re.compile(r'^[0-9]{1,5}(?::[0-9]{1,5})?/(?:tcp|udp)$')
MEDIA_RE = re.compile(r'^[0-9]{1,5}(?::[0-9]{1,5})?/udp$')



def load_module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path, default):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return default
    if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
        raise ValueError('Invalid state file')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('Invalid state document')
    return value


def save_json(path, value):
    data = json.dumps(value, indent=2, sort_keys=True) + '\n'
    fd, temporary = tempfile.mkstemp(prefix='.media-firewall-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)



def registry_ports(registry):
    """Return sorted exact UDP media ports for explicit non-legacy installs."""
    media = load_module('tunnel_media.py', 'media_firewall_plan')
    desired = {}
    for entry in registry.values():
        if not isinstance(entry, dict):
            raise ValueError('Invalid installation record')
        transport = entry.get('mediaTransport')
        if transport is None:
            continue
        validated = media.validate_transport(transport, entry.get('plan'))
        port = validated['port']
        if port in desired:
            raise ValueError('Media UDP port is assigned to multiple tenants')
        desired[port] = f'{port}/udp'
    return [desired[port] for port in sorted(desired)]


def merge_manifest(previous, desired, operator_ports, now=None):
    if previous is None:
        return None
    manager = previous.get('manager')
    if previous.get('configured') is not True or manager not in ('ufw', 'firewalld'):
        return previous
    base = previous.get('ports') or []
    old_media = previous.get('mediaUdpPorts') or []
    old_operator = previous.get('operatorMediaUdpPorts') or []
    for values in (base, old_media, old_operator):
        if not isinstance(values, list) or any(not isinstance(value, str) or not PORT_RE.fullmatch(value) for value in values):
            raise ValueError('Invalid firewall manifest ports')
    if any(not MEDIA_RE.fullmatch(value) for value in old_media + old_operator):
        raise ValueError('Invalid media firewall manifest ports')
    if operator_ports is not None and any(not isinstance(value, str) or not MEDIA_RE.fullmatch(value) for value in operator_ports):
        raise ValueError('Invalid operator media ports')
    base = [value for value in base if value not in old_media and value not in old_operator]
    # Omitting --operator-ports preserves the previously approved operator
    # selection; an explicit empty value clears it.
    operator_values = list(operator_ports) if operator_ports is not None else list(old_operator)
    merged = []
    for value in base + operator_values + list(desired):
        if value not in merged:
            merged.append(value)
    result = dict(previous)
    result['ports'] = merged
    result['mediaUdpPorts'] = list(desired)
    if operator_ports is not None:
        result['operatorMediaUdpPorts'] = operator_values
    elif 'operatorMediaUdpPorts' not in result:
        result['operatorMediaUdpPorts'] = []
    comparable = {key: value for key, value in result.items() if key != 'updatedAt'}
    prior = {key: value for key, value in previous.items() if key != 'updatedAt'}
    if comparable == prior:
        return previous
    result['updatedAt'] = (now or datetime.datetime.now(datetime.timezone.utc)).isoformat()
    return result


def run(command):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          universal_newlines=True, timeout=30)


def ufw_present():
    result = run(['ufw', 'status'])
    if result.returncode:
        raise ValueError('Host firewall status is unavailable')
    present = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and PORT_RE.fullmatch(parts[0]) and parts[1] == 'ALLOW':
            present.add(parts[0])
    return present


def firewalld_present(spec, permanent):
    arguments = ['firewall-cmd']
    if permanent:
        arguments.append('--permanent')
    result = run(arguments + [f'--query-port={spec.replace(":", "-")}'])
    if result.returncode not in (0, 1):
        raise ValueError('Host firewall query failed')
    return result.returncode == 0


def apply_ports(manager, ports):
    if manager == 'ufw':
        present = ufw_present()
        added = []
        for spec in ports:
            if spec in present:
                continue
            result = run(['ufw', 'allow', spec])
            if result.returncode:
                raise ValueError('Host firewall update failed')
            present.add(spec)
            added.append(spec)
        return added
    added = []
    for spec in ports:
        changed = False
        for permanent in (True, False):
            if firewalld_present(spec, permanent):
                continue
            arguments = ['firewall-cmd']
            if permanent:
                arguments.append('--permanent')
            result = run(arguments + [f'--add-port={spec.replace(":", "-")}'])
            if result.returncode:
                raise ValueError('Host firewall update failed')
            changed = True
        if changed:
            added.append(spec)
    return added


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--manifest', default=str(MANIFEST))
    parser.add_argument('--registry', default=str(REGISTRY))
    parser.add_argument('--operator-ports')
    args = parser.parse_args(argv)
    if args.apply and os.geteuid() != 0:
        print('media-udp-firewall: root is required', file=sys.stderr)
        return 2
    try:
        previous = read_json(Path(args.manifest), None)
        registry_path = Path(args.registry)
        registry_exists = registry_path.exists()
        registry = read_json(registry_path, {})
        if not isinstance(registry, dict):
            raise ValueError('Invalid enrollment registry')
        # A missing enrollment registry is not proof that no tenant uses direct
        # media; never erase the recorded selection because a mount is absent.
        if registry_exists:
            desired = registry_ports(registry)
        elif previous is not None:
            # Keep reasserting the persisted selection while a mount is absent.
            desired = list(previous.get('mediaUdpPorts') or [])
        else:
            desired = []
        operator_ports = None
        if args.operator_ports is not None:
            parser_module = load_module('media-udp-ports.py', 'media_firewall_ports')
            operator_ports = [entry if entry.endswith('/udp') else entry + '/udp'
                              for entry in parser_module.parse(args.operator_ports)]
        manifest = merge_manifest(previous, desired, operator_ports)
        result = {'desired': desired, 'operator': operator_ports, 'added': []}
        if manifest is None or manifest.get('configured') is not True or manifest.get('manager') not in ('ufw', 'firewalld'):
            print(json.dumps(result, sort_keys=True))
            return 0
        # Even an unchanged manifest is reasserted: a firewall reload, reboot or
        # operator deletion must not leave the enrolled endpoint closed.
        ports = list(dict.fromkeys(list(manifest.get('mediaUdpPorts') or []) +
                                   list(manifest.get('operatorMediaUdpPorts') or [])))
        if args.apply:
            result['added'] = apply_ports(manifest['manager'], ports)
            if manifest is not previous:
                save_json(Path(args.manifest), manifest)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(f'media-udp-firewall: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
