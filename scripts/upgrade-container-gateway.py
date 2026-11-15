#!/usr/bin/env python3
"""Upgrade the standard Compose gateway and promote the reviewed host bundle.

Enrollment state, credentials, certificates, media keys, transport choices and
tenant identity are never rewritten by this tool. The host installer owns the
generated files of each managed media link, and this tool only regenerates them
from the promoted renderer for links that are already active and managed.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
SERVICE = 'sokrat-gateway'
BUNDLE = Path('/usr/local/lib/sokrat-tenant-provisioning')
ETC_ROOT = Path('/etc/sokrat')
UNIT_ROOT = Path('/etc/systemd/system')
MEDIA_ID = re.compile(r'pbx_[a-f0-9]{16}')
# Only installer-generated, non-secret files may be refreshed or restored.
GENERATED_MEDIA_FILES = ('media.conf', 'plan.json', 'transport.json', 'link-up', 'link-down')
NEW_TLS_DEFAULTS = {'GATEWAY_TLS_ENABLED': 'auto', 'GATEWAY_HTTPS_PORT': '443',
                    'GATEWAY_WSS_PORT': '8089'}
# The one reviewed way to move a tenant off the legacy FRP TCP media proxy.
LEGACY_MEDIA_ACTION = (
    'Convert each tenant explicitly with media-transport-transaction.py: prepare the gateway role, '
    'prepare the PBX role from that gateway peer bundle, apply both, then verify the gateway role '
    'of the same transaction.'
)


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


def promote_host_bundle(env):
    """Promote the reviewed host bundle without rebuilding media state or PKI.

    The existing provisioning installer backs up prior bundle files, keeps
    /etc/sokrat and credentials untouched, stops only its own units, and
    restarts only previously active ones. Media and Asterisk are not touched.
    """
    if not (BUNDLE / 'tunnel-enrollment.py').is_file():
        raise Refusal('host provisioning bundle is incomplete; promote it explicitly')
    command = [sys.executable, str(ROOT / 'scripts/install-provisioning-worker.py'), '--apply']
    for attempt in range(3):
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, check=True,
                                    timeout=900, capture_output=True, text=True)
            if result.stdout:
                sys.stdout.write(result.stdout)
            return
        except subprocess.CalledProcessError as error:
            # The provisioning timer/reconcile may briefly own the shared lock.
            if error.returncode == 2 and attempt < 2:
                time.sleep(5)
                continue
            raise Refusal('host provisioning bundle promotion failed') from None
        except (OSError, subprocess.SubprocessError):
            raise Refusal('host provisioning bundle promotion failed') from None


def trusted_json(path, default=None):
    """Read root-owned enrollment state; refuse replaceable path components."""
    try:
        for directory in [path.parent, *path.parent.parents]:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Refusal('enrolled state directory is untrusted')
        info = path.lstat()
    except FileNotFoundError:
        return default
    except OSError:
        raise Refusal('enrolled state is unreadable') from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077 or info.st_size > 2 * 1024 * 1024):
        raise Refusal('enrolled state is untrusted')
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Refusal('enrolled state is unreadable') from None
    with os.fdopen(descriptor, 'rb') as stream:
        try:
            opened = os.fstat(stream.fileno())
        except OSError:
            raise Refusal('enrolled state is unreadable') from None
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
                or opened.st_mode & 0o077 or opened.st_size > 2 * 1024 * 1024):
            raise Refusal('enrolled state is untrusted')
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise Refusal('enrolled state is untrusted')
    try:
        return json.loads(raw)
    except ValueError:
        raise Refusal('enrolled state is invalid') from None


def enrolled_media_unit(unit_root, pbx_id):
    return unit_root / ('sokrat-media-' + pbx_id + '.service')


def run_systemctl(env, argv):
    try:
        return subprocess.run(['systemctl', *argv], env=env, timeout=40,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    except (OSError, subprocess.SubprocessError):
        raise Refusal('enrolled media service control failed') from None


def load_media_installer(media_root, unit_root):
    """Load the promoted media installer and its pure modules for this host."""
    if not (BUNDLE / 'install-media-link.py').is_file():
        raise Refusal('host media installer is missing from the promoted bundle')
    saved = list(sys.path)
    sys.path.insert(0, str(BUNDLE))
    try:
        installer_spec = importlib.util.spec_from_file_location(
            'sokrat_promoted_media_installer', BUNDLE / 'install-media-link.py')
        installer = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer)
        material_spec = importlib.util.spec_from_file_location(
            'sokrat_promoted_media_material', BUNDLE / 'tunnel_media_material.py')
        material = importlib.util.module_from_spec(material_spec)
        material_spec.loader.exec_module(material)
    except Exception:
        raise Refusal('promoted host media installer cannot be loaded') from None
    finally:
        sys.path[:] = saved
    # The installer writes below these roots; a mounted deployment may keep
    # /etc/sokrat elsewhere, so bind its reviewed defaults to the real paths.
    installer.ROOT = media_root
    installer.UNIT_ROOT = unit_root
    return installer, material


def report_legacy_media(pbx_ids):
    """Name the active tenants that keep the legacy FRP TCP media proxy.

    Nothing is changed or deleted here: this is the explicit policy finding the
    upgrade refuses to hide behind a green "completed" line.
    """
    if not pbx_ids:
        return
    print('%d active tenant(s) still carry media over the legacy FRP TCP proxy and are not UDP-ready: %s'
          % (len(pbx_ids), ', '.join(pbx_ids)), file=sys.stderr, flush=True)
    print(LEGACY_MEDIA_ACTION, file=sys.stderr, flush=True)


def provisioning_lock(installer, etc_root, timeout=60):
    """Hold the shared root provisioning lock for the whole media phase.

    Enrollment, tenant reconciliation and the provisioning worker take this
    exact lock, so a cooperating identity or material change cannot interleave
    with the preflight and apply below. The wait is bounded: a busy worker is a
    clear refusal, never an indefinite upgrade hang.
    """
    config = trusted_json(etc_root / 'gateway-provisioning.json', {})
    if not isinstance(config, dict):
        raise Refusal('enrolled provisioning configuration is invalid')
    directory = Path(config.get('lockDir', '/run/sokrat-tenant-provisioning'))
    if not directory.is_absolute():
        raise Refusal('enrolled provisioning lock directory is invalid')
    try:
        installer.private_directory(directory)
        descriptor = os.open(str(directory / 'lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
                             | os.O_NONBLOCK, 0o600)
    except (OSError, ValueError):
        raise Refusal('enrolled provisioning lock is unavailable') from None
    stream = os.fdopen(descriptor, 'r+b')
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        stream.close()
        raise Refusal('enrolled provisioning lock is untrusted')
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return stream
        except OSError:
            if time.monotonic() >= deadline:
                stream.close()
                raise Refusal('tenant provisioning worker is busy; retry the upgrade') from None
            time.sleep(1)


def enrolled_media_material(material_module, enrollment_root, pbx_id):
    document = trusted_json(enrollment_root / pbx_id / 'material.json')
    if not isinstance(document, dict):
        raise Refusal('enrolled media credentials are missing for ' + pbx_id)
    try:
        return material_module.for_role(document, 'gateway')
    except (KeyError, TypeError, ValueError):
        raise Refusal('enrolled media credentials are invalid for ' + pbx_id) from None


def validate_enrolled_media_link(installer, material_module, media_root, enrollment_root,
                                 unit_root, pbx_id, record):
    """Prove registry, installed plan/transport and credential identity agree."""
    try:
        plan = installer.validate_plan(record.get('plan'))
        transport = installer.validate_transport(record.get('mediaTransport'), plan)
    except (TypeError, ValueError):
        raise Refusal('enrolled media plan or transport is invalid for ' + pbx_id) from None
    if plan['pbxId'] != pbx_id:
        raise Refusal('enrolled media plan identity differs from the registry record for ' + pbx_id)
    directory = media_root / pbx_id
    try:
        info = directory.lstat()
    except FileNotFoundError:
        raise Refusal('installed media directory is missing for ' + pbx_id) from None
    except OSError:
        raise Refusal('installed media directory is unreadable for ' + pbx_id) from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refusal('installed media directory is untrusted for ' + pbx_id)
    installed_plan = trusted_json(directory / 'plan.json')
    try:
        installer.validate_plan(installed_plan)
    except (TypeError, ValueError):
        raise Refusal('installed media plan is invalid for ' + pbx_id) from None
    if installed_plan != plan:
        raise Refusal('installed media plan differs from enrollment for ' + pbx_id)
    installed_transport = trusted_json(directory / 'transport.json')
    try:
        installer.validate_transport(installed_transport, plan)
    except (TypeError, ValueError):
        raise Refusal('installed media transport is invalid for ' + pbx_id) from None
    if installed_transport != transport:
        raise Refusal('installed media transport differs from enrollment for ' + pbx_id)
    material = enrolled_media_material(material_module, enrollment_root, pbx_id)
    for name, value in material.items():
        path = directory / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise Refusal('enrolled media credential is missing for ' + pbx_id) from None
        except OSError:
            raise Refusal('enrolled media credential is unreadable for ' + pbx_id) from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise Refusal('enrolled media credential is untrusted for ' + pbx_id)
        try:
            current = path.read_text()
        except (OSError, ValueError):
            raise Refusal('enrolled media credential is unreadable for ' + pbx_id) from None
        if current != value:
            raise Refusal('enrolled media credentials differ from enrollment for ' + pbx_id)
    unit = enrolled_media_unit(unit_root, pbx_id)
    # Every selected link's generated files are proven safe before any write,
    # so a later unsafe tenant cannot abort after an earlier one was changed.
    return (directory, unit, {'plan': plan, 'transport': transport, 'material': material},
            generated_media_state(directory, unit))


def generated_media_state(directory, unit):
    """Capture only generated, non-secret files with their exact metadata."""
    state = {}
    for path in [*(directory / name for name in GENERATED_MEDIA_FILES), unit]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            state[path] = None
            continue
        except OSError:
            raise Refusal('generated media state is unreadable') from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise Refusal('generated media state is untrusted')
        state[path] = (path.read_text(), stat.S_IMODE(info.st_mode))
    return state


def restore_generated_media(installer, before, after):
    """Restore changed generated files unless a concurrent writer replaced them."""
    restored = True
    for path, original in before.items():
        current = after.get(path)
        if current == original:
            continue
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022
                    or (path.read_text(), stat.S_IMODE(info.st_mode)) != current):
                restored = False
                continue
            if original is None:
                path.unlink()
            else:
                installer.write(path, original[0], original[1])
        except (OSError, ValueError):
            restored = False
    return restored


def converge_enrolled_media_link(installer, env, directory, unit, document, before):
    """Regenerate one active managed link; restart it only if a file changed.

    The exact content and mode this installer writes is recorded through its own
    write helper, so a rollback restores a file only while it still holds our
    output. Credential files are never written or restored here: the installer
    is expected to leave them untouched because their bytes and mode were
    already proven to match enrollment.
    """
    written = {}
    original_write = installer.write

    def record_write(path, data, mode):
        path = Path(path)
        if path not in before:
            # The installer offers credentials to write() even when unchanged.
            # Accept that no-op without ever letting it replace credential bytes.
            material = document['material']
            if (path.parent != directory or path.name not in material
                    or data != material[path.name] or mode != 0o600):
                raise Refusal('media installer attempted a non-generated write')
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != mode or path.read_text() != data):
                raise Refusal('enrolled media credentials changed during refresh')
            return False
        changed = original_write(path, data, mode)
        if changed:
            written[path] = (data, mode)
        return changed

    failed = False
    installer.write = record_write
    try:
        installer.install(document, 'gateway', False)
    except Exception:
        failed = True
    finally:
        installer.write = original_write
    expected = {path: written.get(path, state) for path, state in before.items()}
    if failed:
        restored = restore_generated_media(installer, before, expected)
        if not restored:
            raise Refusal('enrolled media refresh failed and generated state changed concurrently') from None
        raise Refusal('enrolled media refresh failed; generated state restored') from None
    changed = [path for path in before if before[path] != expected[path]]
    if not changed:
        return False
    try:
        if unit in changed and run_systemctl(env, ['daemon-reload']) != 0:
            raise Refusal('enrolled media service reload failed')
        if run_systemctl(env, ['restart', unit.name]) != 0:
            raise Refusal('enrolled media restart failed')
    except Refusal:
        if not restore_generated_media(installer, before, expected):
            raise Refusal('enrolled media restart failed and generated state changed concurrently; '
                          'operator recovery required') from None
        if unit in changed and run_systemctl(env, ['daemon-reload']) != 0:
            raise Refusal('enrolled media restart failed and the previous media unit could not reload; '
                          'operator recovery required') from None
        if run_systemctl(env, ['restart', unit.name]) != 0:
            raise Refusal('enrolled media restart failed and the previous media service did not recover') from None
        raise Refusal('enrolled media restart failed; previous generated state and service restored') from None
    return True


def refresh_enrolled_media(env, etc_root=ETC_ROOT, unit_root=UNIT_ROOT):
    """Converge active managed media links to the promoted renderer.

    Runs after host-bundle promotion and before the firewall and tenant phases,
    so a stale generated media.conf cannot survive an otherwise successful
    upgrade. Enrollment, reconciliation and the provisioning worker are excluded
    by their own shared lock for the whole read/validate/apply sequence. Only
    links whose unit is active and carries the installer marker are selected:
    stopped links are never started and unmanaged units are never overwritten.
    Every selected link's registry plan, installed plan, transport, credential
    bytes and generated files are proven before any write. Identity, transport,
    ports, peers, FRP and firewall state are untouched. A link is restarted only
    when the installer rewrote one of its generated files; a failure restores
    the affected generated files (unless a concurrent writer already replaced
    them) and the previous service where that is possible, then aborts.

    Active registry rows without an explicit transport still use the legacy FRP
    TCP media proxy. They are converged and left running (legacy tenants keep
    working, nothing is deleted), reported to the operator, and returned so the
    upgrade does not claim success while they are not UDP-ready.
    """
    enrollment_root = etc_root / 'tunnel-enrollment'
    registry_path = enrollment_root / 'installations.json'
    try:
        registry_path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise Refusal('enrolled media registry is unreadable') from None
    media_root = etc_root / 'media'
    installer, material_module = load_media_installer(media_root, unit_root)
    lock = provisioning_lock(installer, etc_root)
    converged = 0
    try:
        registry = trusted_json(registry_path)
        if not isinstance(registry, dict):
            raise Refusal('enrolled media registry is invalid')
        if not registry:
            return
        selected = []
        for record in registry.values():
            pbx_id = record.get('pbxId') if isinstance(record, dict) else None
            if not isinstance(pbx_id, str) or not MEDIA_ID.fullmatch(pbx_id):
                raise Refusal('enrolled media record is invalid')
            unit = enrolled_media_unit(unit_root, pbx_id)
            # A stopped or absent link is the operator's choice; never start it.
            if run_systemctl(env, ['is-active', '--quiet', unit.name]) != 0:
                continue
            try:
                info = unit.lstat()
                content = unit.read_text() if stat.S_ISREG(info.st_mode) else None
            except OSError:
                raise Refusal('enrolled media unit is unreadable for ' + pbx_id) from None
            if content is None:
                raise Refusal('enrolled media unit is not a regular file for ' + pbx_id)
            if not content.startswith(installer.MARKER):
                raise Refusal('active media unit is not managed by Sokrat for ' + pbx_id)
            selected.append((pbx_id, record))
        links = []
        legacy = []
        for pbx_id, record in selected:
            link = validate_enrolled_media_link(installer, material_module, media_root,
                                                enrollment_root, unit_root, pbx_id, record)
            # The installer's own transport check returned None: this registry
            # row has no explicit transport, so media still rides the FRP TCP
            # proxy. It stays converged and untouched, but never UDP-ready.
            if link[2]['transport'] is None:
                legacy.append(pbx_id)
            links.append(link)
        report_legacy_media(legacy)
        converged = sum(converge_enrolled_media_link(installer, env, *link) for link in links)
    finally:
        lock.close()
    if converged:
        print('Refreshed %d active enrolled media link(s) to the promoted renderer.' % converged,
              flush=True)
    return legacy


def reassert_media_firewall(env):
    """Reassert persisted UDP media endpoints from the promoted host bundle.

    The container has no host firewall authority, so this runs on the host with
    the bundle just promoted. The helper is additive and idempotent: it opens
    only ports of registry rows that already carry an explicit mediaTransport,
    preserves operator/manual rules and never deletes a rule.
    """
    helper = BUNDLE / 'media-udp-firewall.py'
    if not helper.is_file():
        raise Refusal('host media firewall helper is missing from the promoted bundle')
    try:
        result = subprocess.run([sys.executable, str(helper), '--apply'], env=env,
                                timeout=60, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        raise Refusal('host UDP media firewall reconcile failed') from None
    if result.returncode != 0:
        raise Refusal('host UDP media firewall reconcile failed')


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
    allowed = {'build', 'command', 'entrypoint', 'container_name', 'depends_on', 'environment', 'healthcheck', 'image', 'logging',
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
    # Reverse media and enrollment run on the host. Their reviewed bundle is
    # part of the installed deployment and must be promotable before recreation.
    etc_source = next((Path(m['source']) for m in service['volumes'] if m['target'] == '/etc/sokrat'), None)
    host_enrollment = bool(etc_source and (etc_source / 'tunnel-enrollment' / 'config.json').exists())
    if host_enrollment and not (BUNDLE / 'tunnel-enrollment.py').is_file():
        raise Refusal('host provisioning bundle is incomplete; promote it explicitly before upgrading')
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
    legacy_media = None
    if host_enrollment:
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
    # Host media/enrollment code is outside the image. Promote the reviewed
    # bundle after the new container is running so a failed build changes no
    # host files; the installer preserves credentials, certificates and units.
    if host_enrollment:
        promote_host_bundle(env)
        # Persisted media configuration is owned by the promoted renderer;
        # converge active managed links before the firewall/tenant phases.
        legacy_media = refresh_enrolled_media(env, etc_root=etc_source)
        reassert_media_firewall(env)
    # Tenant coturn processes are not managed by supervisor. A recreated
    # container must re-evaluate current authority and restart eligible relays,
    # not merely reuse a persisted pre-recreation "ready" status.
    run(['docker', 'exec', SERVICE, '/bin/sh', '-ec',
         'if [ -f /etc/sokrat/gateway-provisioning.json ]; then '
         'exec /usr/bin/python3 /usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py --apply; fi'], env)
    if legacy_media:
        # The upgrade finished and already-UDP tenants are converged, but the
        # legacy rows still carry media over FRP TCP: never report success for
        # an installation that is not UDP-only. The operator instructions were
        # printed by refresh_enrolled_media above.
        print('Upgrade completed without deleting or rewriting legacy media state, but %d active '
              'tenant(s) are still on the legacy FRP TCP media proxy; not reporting success.'
              % len(legacy_media), file=sys.stderr, flush=True)
        return 2
    print('Compose recreation and tenant reconciliation completed. Verify provider status and real PBX wake; no production acceptance is implied.')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Refusal, IndexError, KeyError, TypeError) as exc:
        print('Upgrade refused or failed: ' + (str(exc) if isinstance(exc, Refusal) else 'unexpected Docker inspection data'), file=sys.stderr)
        sys.exit(2)
