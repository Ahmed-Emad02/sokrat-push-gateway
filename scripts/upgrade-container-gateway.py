#!/usr/bin/env python3
"""Upgrade the existing standard Compose gateway, without rewriting host state."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SERVICE = 'sokrat-gateway'
NEW_TLS_DEFAULTS = {'GATEWAY_TLS_ENABLED': 'auto', 'GATEWAY_HTTPS_PORT': '443',
                    'GATEWAY_WSS_PORT': '8089'}


class Refusal(Exception):
    pass


def run(argv, env, capture=True):
    try:
        return subprocess.run(argv, cwd=ROOT, env=env, check=True, text=True,
                              stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.PIPE if capture else None).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        # Docker output can contain configuration secrets; never repeat it.
        raise Refusal('Docker command failed: ' + ' '.join(argv[:3])) from exc


def docker_json(argv, env):
    try:
        return json.loads(run(['docker'] + argv, env))
    except (TypeError, ValueError) as exc:
        raise Refusal('Docker returned invalid inspection data') from exc


def env_map(items):
    result = {}
    for item in items or []:
        key, separator, value = item.partition('=')
        if not separator or not key or key in result:
            raise Refusal('existing container environment is ambiguous')
        result[key] = value
    return result


def check_mounts(service, container):
    desired = {}
    for mount in service.get('volumes', []):
        if mount.get('type') != 'bind' or not mount.get('source') or not mount.get('target'):
            raise Refusal('only the standard bind-mount deployment is supported')
        options = mount.get('bind') or {}
        if set(options) - {'create_host_path'}:
            raise Refusal('custom bind options require a reviewed migration')
        target = mount['target']
        if target in desired:
            raise Refusal('duplicate mount target')
        source = Path(mount['source'])
        if not source.is_absolute() or not source.is_dir():
            raise Refusal('a bind-mount source is missing or invalid')
        desired[target] = (os.path.realpath(source), not bool(mount.get('read_only', False)))
    actual = {}
    for mount in container.get('Mounts', []):
        if (mount.get('Type') != 'bind' or mount.get('Destination') in actual
                or mount.get('Propagation') not in (None, '', 'rprivate')):
            raise Refusal('existing container has unsupported mounts')
        actual[mount['Destination']] = (os.path.realpath(mount['Source']), bool(mount['RW']))
    if not desired or desired != actual:
        raise Refusal('existing bind mounts differ from the Compose configuration')


def validate(service, container, image):
    allowed = {'build', 'command', 'entrypoint', 'container_name', 'environment', 'image', 'logging',
               'network_mode', 'restart', 'volumes'}
    if (set(service) - allowed or service.get('container_name') != SERVICE
            or service.get('command') is not None or service.get('entrypoint') is not None):
        raise Refusal('custom Compose service configuration requires a reviewed migration')
    host = container.get('HostConfig') or {}
    config = container.get('Config') or {}
    base = image.get('Config') or {}
    if service.get('network_mode') != 'host' or host.get('NetworkMode') != 'host':
        raise Refusal('only the standard host-network deployment is supported')
    if host.get('RestartPolicy', {}).get('Name') != service.get('restart'):
        raise Refusal('existing restart policy differs from Compose')
    logging = service.get('logging') or {}
    actual_logging = host.get('LogConfig') or {}
    if (logging.get('driver') != actual_logging.get('Type')
            or (logging.get('options') or {}) != (actual_logging.get('Config') or {})):
        raise Refusal('existing logging configuration differs from Compose')
    for name in ('Privileged', 'CapAdd', 'CapDrop', 'SecurityOpt', 'Devices',
                 'PortBindings', 'ExtraHosts', 'Dns', 'DnsSearch', 'DnsOptions',
                 'Memory', 'MemorySwap', 'NanoCpus', 'CpuShares', 'CpuQuota',
                 'CpusetCpus', 'CpusetMems', 'PidsLimit', 'Sysctls', 'Init'):
        if host.get(name):
            raise Refusal('existing container has unsupported host customizations')
    for name in ('User', 'Entrypoint', 'Cmd', 'WorkingDir', 'Healthcheck', 'StopSignal'):
        if (config.get(name) or None) != (base.get(name) or None):
            raise Refusal('existing container has unsupported runtime customizations')
    expected = env_map(base.get('Env'))
    variables = service.get('environment') or {}
    if not isinstance(variables, dict) or any(value is None for value in variables.values()):
        raise Refusal('Compose environment contains unresolved variables')
    expected.update({key: str(value) for key, value in variables.items()})
    actual = env_map(config.get('Env'))
    # Older images predate these optional Compose settings. Admit only their
    # exact shipped defaults when absent; never absorb arbitrary env drift.
    for key, value in NEW_TLS_DEFAULTS.items():
        if key not in actual and key not in env_map(base.get('Env')) and expected.get(key) == value:
            expected.pop(key)
    if actual != expected:
        raise Refusal('existing container environment differs from Compose; no values displayed')
    check_mounts(service, container)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='build and recreate the gateway after preflight')
    args = parser.parse_args()
    if not (ROOT / '.env').is_file() or not (ROOT / 'docker-compose.yml').is_file():
        raise Refusal('existing .env and docker-compose.yml are required')
    # Do not allow caller shell variables or COMPOSE_FILE to silently override
    # the installed .env. Preserve only Docker client discovery settings.
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'DOCKER_CONFIG', 'TMPDIR') if key in os.environ}
    contexts = docker_json(['context', 'inspect'], env)
    host = contexts[0].get('Endpoints', {}).get('docker', {}).get('Host', '')
    if not host.startswith('unix://'):
        raise Refusal('only a local Unix-socket Docker context is supported')
    containers = docker_json(['inspect', '--type', 'container', SERVICE], env)
    container = containers[0]
    container_id = container.get('Id', '')
    if not re.fullmatch(r'[0-9a-f]{64}', container_id):
        raise Refusal('existing container ID is invalid')
    if not container.get('State', {}).get('Running'):
        raise Refusal('existing gateway container must be running')
    labels = container.get('Config', {}).get('Labels') or {}
    project = labels.get('com.docker.compose.project', '')
    workdir = labels.get('com.docker.compose.project.working_dir', '')
    files = labels.get('com.docker.compose.project.config_files', '')
    if (not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', project)
            or labels.get('com.docker.compose.service') != SERVICE
            or os.path.realpath(workdir) != str(ROOT)
            or files != str(ROOT / 'docker-compose.yml')):
        raise Refusal('container was not created by this directory and its single Compose file')
    compose = ['docker', 'compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'docker-compose.yml'), '-p', project]
    try:
        doc = json.loads(run(compose + ['config', '--format', 'json'], env))
        service = doc['services'][SERVICE]
    except (ValueError, KeyError, TypeError) as exc:
        raise Refusal('Compose configuration is invalid or unsupported') from exc
    image_id = container.get('Image', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise Refusal('existing image ID is invalid')
    image = docker_json(['image', 'inspect', image_id], env)[0]
    validate(service, container, image)
    build_args = (service.get('build') or {}).get('args') or {}
    for flag, key in (('-u', 'SOKRAT_UID'), ('-g', 'SOKRAT_GID')):
        current = run(['docker', 'exec', SERVICE, 'id', flag, 'sokrat-push'], env).strip()
        if not current.isdigit() or str(build_args.get(key, '')) != current:
            raise Refusal('service account IDs differ from the installed container')
    print('Preflight passed. Previous image: ' + image_id, flush=True)
    if not args.apply:
        print('Dry run only: no build, recreation, or host-state changes.')
        return
    # Reverse media runs on the host, not in a NET_ADMIN-enabled container.
    # Only opted-in reverse-TLS installations need these host packages.
    etc_source = next(Path(m['source']) for m in service['volumes'] if m['target'] == '/etc/sokrat')
    if (etc_source / 'tunnel-enrollment' / 'config.json').exists():
        run(['bash', str(ROOT / 'scripts/install-reverse-tls-deps.sh')], env, capture=False)
    run(compose + ['build', SERVICE], env, capture=False)
    # Do not recreate a replacement container or apply a changed .env/Compose
    # configuration if another operator changed it while the image was building.
    try:
        current_doc = json.loads(run(compose + ['config', '--format', 'json'], env))
    except (ValueError, TypeError) as exc:
        raise Refusal('Compose configuration changed during build') from exc
    current = docker_json(['inspect', '--type', 'container', SERVICE], env)[0]
    if (current_doc != doc or current.get('Id') != container_id
            or current.get('Image') != image_id or not current.get('State', {}).get('Running')):
        raise Refusal('gateway or Compose configuration changed during build; no recreation performed')
    run(compose + ['up', '-d', '--no-deps', '--no-build', SERVICE], env, capture=False)
    # Tenant coturn processes are not managed by supervisor. A recreated
    # container must re-evaluate current authority and restart eligible relays,
    # not merely reuse a persisted pre-recreation "ready" status.
    run(['docker', 'exec', SERVICE, '/bin/sh', '-ec',
         'if [ -f /etc/sokrat/gateway-provisioning.json ]; then '
         'exec /usr/bin/python3 /usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py --apply; fi'], env)
    print('Compose recreation and tenant reconciliation completed. Verify provider status and real PBX wake; no production acceptance is implied.')


if __name__ == '__main__':
    try:
        main()
    except (Refusal, IndexError, KeyError, TypeError) as exc:
        print('Upgrade refused or failed: ' + (str(exc) if isinstance(exc, Refusal) else 'unexpected Docker inspection data'), file=sys.stderr)
        sys.exit(2)
