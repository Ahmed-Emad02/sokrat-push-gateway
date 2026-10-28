#!/usr/bin/env python3
"""Bounded, root-run one-shot reconcile worker for per-PBX tenant provisioning.

WHY
  Adding a customer PBX to the gateway touches three independent planes:
  the local isolated TURN relay (root/systemd/ufw), the cloud firewall (provider
  API) and the customer PBX dialplan (SSH or PBX API). Doing that from the web
  dashboard would mean the dashboard can name an executable and a remote target,
  which is a root-execution primitive. This worker keeps that authority in
  root-owned configuration instead: the dashboard can create records, but only a
  root operator can authorize provisioning of a specific PBX identity.

WHAT IT DOES (one bounded run, normally from a systemd timer)
  1. Reads the root-private worker config (default
     /etc/sokrat/gateway-provisioning.json) and the dashboard control store.
  2. Refuses the whole run unless every PBX the worker is about to touch is
     pinned in that config (PBX id + expected wsURL/apiURL/mediaIps + expected
     management status + SHA-256 of exactly those fields). The web dashboard
     never supplies an executable, a host to SSH to, or credentials.
  3. Refuses the whole run unless every *existing* allocation in
     tenant-plan.json is pinned too. sync-tenant-runtime.py revokes any
     allocation that has no enabled record in its input, so feeding it a
     filtered snapshot while leaving an unlisted allocation behind would
     silently stop another customer's relay. "Refuse" is the safe answer.
  4. Reuses the bundled sync-tenant-runtime.py (subprocess, never a shell) with a
     root-private filtered snapshot that contains only pinned records. Records
     that are pinned but disabled are passed as enabled=false, which is the
     documented sync behaviour for a disabled PBX (stop unit, remove ufw rules,
     remove service secret copy; allocation/token retained).
  5. Calls the trusted cloud firewall adapter for every enabled PBX, verifies the
     relay manifest entry (host, port, pinned peers, derived private secret) and
     that the isolated unit is active, then calls the per-PBX trusted hook
     adapter to install the PBX-side push hook. A disabled known PBX is not sent
     to any adapter: cloud firewall policy is intentionally retained and no hook
     is installed.
  6. Writes a sanitized status document atomically (0640 root:<service group>)
     for the service to read. It never writes control.json, never approves
     devices, never enables global routing and never restarts the shared runtime.

TRUST MODEL
  * The worker, sync script and adapters must live in the root-owned bundle
    /usr/local/lib/sokrat-tenant-provisioning (installed by
    scripts/install-provisioning-worker.py). The application directory
    /opt/sokrat-push-gateway is service-owned, so nothing there is executable
    authority. In production mode this worker refuses to run from anywhere else.
  * Every helper path, the config and the status parent must be root-owned,
    free of symlinks and not writable by group/other.
  * Adapters are invoked as argv [exe, pbxId] with a JSON request on stdin, a
    sanitized environment, a timeout, and stdout/stderr discarded. No shell is
    ever used. The PBX hook token appears only in the hook adapter request and
    is never logged, printed or written to the status file.
  * The dashboard control store is hashed before the relay stage and re-read
    before every privileged stage and before reporting ready. Any dashboard edit
    aborts the run without a stale ready result.
  * The run lock is a non-blocking flock held until exit, so SIGKILL cannot
    leave a stale lock. Dry-run performs no writes, no commands and creates no
    lock.

STATUS SCHEMA (schemaVersion 1)
  {"schemaVersion": 1, "updatedAt": "<ISO-8601 Z>",
   "pbx": {"<pbxId>": {"state": "ready"|"blocked"|"error"|"planned",
                       "stages": {"relay": ..., "firewall": ..., "hook": ...},
                       "reason": "<allowlisted reason>",
                       "fingerprint": "<sha256>"|null,
                       "capturedUpdatedAt": "<record updatedAt>"|null}}}
  stage values: pending | ready | blocked | error | planned | skipped
  reasons:      not_configured | identity_mismatch | approval_required |
                relay_failed | firewall_required | firewall_failed |
                hook_required | hook_failed | ready | planned | stale |
                worker_failed | configuration_invalid
  capturedUpdatedAt lets a reader compare the record revision used for this run
  with the current dashboard record; updatedAt is refreshed on every run, even
  when sync and adapters were skipped.

USAGE
  # Validate and print the plan. No writes, no commands, no lock creation.
  /usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py --dry-run

  # Apply (root). This is what systemd/sokrat-tenant-provisioning.service runs.
  /usr/bin/python3 /usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py --apply

  # Staging/tests only: relax root/bundle ownership requirements.
  ./scripts/reconcile-tenant-provisioning.py --apply --allow-unprivileged \\
      --config /path/to/fixture.json

EXIT CODES
  0  no error state (ready/planned/blocked, including a safe global refusal)
  1  at least one PBX is in error state, or the worker itself failed
  2  global refusal before any change (configuration/identity/allocation gate)
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import urllib.parse

STATUS_SCHEMA_VERSION = 1
CONFIG_SCHEMA_VERSION = 1

# Deployment bundle: installed root-owned and immutable for the service user.
TRUSTED_BUNDLE = Path("/usr/local/lib/sokrat-tenant-provisioning")

DEFAULT_CONFIG = "/etc/sokrat/gateway-provisioning.json"
DEFAULT_LOCK_DIR = "/run/sokrat-tenant-provisioning"
DEFAULT_STATUS_FILE = "/var/lib/sokrat-tenant-provisioning/status.json"
DEFAULT_CONTROL_FILE = "/var/lib/sokrat-gateway/control.json"
DEFAULT_STATE_DIR = "/var/lib/sokrat-gateway"
DEFAULT_TURN_ROOT = "/etc/sokrat/turn"
DEFAULT_UNIT_DIR = "/etc/systemd/system"
DEFAULT_SERVICE_USER = "sokrat-push"
DEFAULT_IFACE = "tailscale0"

UNIT_TEMPLATE = "sokrat-tenant-turn@.service"

# Mirrors scripts/sync-tenant-runtime.py: the allocation plan is service-writable
# and therefore untrusted, so its arithmetic is re-derived here before any port
# reaches a root adapter or a systemd unit name is trusted.
LISTENER_BASE = 3500
LISTENER_SLOTS = 500
RELAY_BASE = 50000
RELAY_SPAN = 100
MAX_SLOTS = min(LISTENER_SLOTS, (65535 - RELAY_BASE + 1) // RELAY_SPAN)
RESERVED_LISTENER_PORTS = {22, 80, 443, 3478, 8088, 8095, 9096, 9097}

SYNC_TIMEOUT = 300
ADAPTER_TIMEOUT = 360
SYSTEMCTL_TIMEOUT = 20
MAX_SYNC_OUTPUT = 1024 * 1024

PBX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,18}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,200}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

STATES = frozenset({"ready", "blocked", "error", "planned"})
STAGE_VALUES = frozenset({"pending", "ready", "blocked", "error", "planned", "skipped"})
REASONS = frozenset({
    "not_configured",
    "identity_mismatch",
    "approval_required",
    "relay_failed",
    "firewall_required",
    "firewall_failed",
    "hook_required",
    "hook_failed",
    "ready",
    "planned",
    "stale",
    "worker_failed",
    "configuration_invalid",
})

APPROVALS = frozenset({"approved", "unmanaged", "pending"})

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class Refusal(Exception):
    """A safe refusal. Carries an allowlisted reason and a non-secret message."""

    def __init__(self, reason, message):
        assert reason in REASONS, reason
        super().__init__(message)
        self.reason = reason


class ControlChanged(Exception):
    """The dashboard control store changed while privileged work was running."""


def refuse(reason, message):
    raise Refusal(reason, message)


# ---------------------------------------------------------------------------
# Small filesystem primitives
# ---------------------------------------------------------------------------


def absolute(value):
    return Path(os.path.abspath(str(value)))


def lstat_or_none(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        refuse("configuration_invalid", f"cannot inspect {path}: {error.strerror}")


def check_dir_chain(path, owners, label):
    """Every component of `path` (inclusive) must be a safe root-owned dir."""
    current = absolute(path)
    for component in [current, *current.parents]:
        info = lstat_or_none(component)
        if info is None:
            refuse("configuration_invalid", f"{label} component is missing: {component}")
        if stat.S_ISLNK(info.st_mode):
            refuse("configuration_invalid", f"{label} component is a symlink: {component}")
        if not stat.S_ISDIR(info.st_mode):
            refuse("configuration_invalid", f"{label} component is not a directory: {component}")
        if info.st_mode & 0o022:
            refuse(
                "configuration_invalid",
                f"{label} component is writable by group/other: {component}",
            )
        if info.st_uid not in owners:
            refuse(
                "configuration_invalid",
                f"{label} component has an unexpected owner: {component}",
            )


def check_file(path, label, owners, private=False, executable=False, must_exist=True):
    """Return lstat for a safe regular file. `private` forbids group/other bits."""
    target = absolute(path)
    info = lstat_or_none(target)
    if info is None:
        if must_exist:
            refuse("configuration_invalid", f"{label} not found: {target}")
        return None
    if stat.S_ISLNK(info.st_mode):
        refuse("configuration_invalid", f"{label} is a symlink: {target}")
    if not stat.S_ISREG(info.st_mode):
        refuse("configuration_invalid", f"{label} is not a regular file: {target}")
    if private:
        if info.st_mode & 0o077:
            refuse(
                "configuration_invalid",
                f"{label} must not be accessible by group/other "
                f"(mode {oct(info.st_mode & 0o777)}): {target}",
            )
    elif info.st_mode & 0o022:
        refuse(
            "configuration_invalid",
            f"{label} must not be writable by group/other "
            f"(mode {oct(info.st_mode & 0o777)}): {target}",
        )
    if executable and not info.st_mode & 0o111:
        refuse("configuration_invalid", f"{label} is not executable: {target}")
    if info.st_uid not in owners:
        refuse(
            "configuration_invalid",
            f"{label} has an unexpected owner (uid {info.st_uid}): {target}",
        )
    check_dir_chain(target.parent, owners, label)
    return info


def read_regular(path, label):
    descriptor = os.open(absolute(path), os.O_RDONLY | NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def fsync_directory(directory):
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def atomic_write(path, text, mode, uid=0, gid=0, test_mode=False, owners=None):
    """Write a file atomically with its final mode/owner before it is visible."""
    target = absolute(path)
    if owners is None:
        owners = {0, os.geteuid()} if test_mode else {0}
    check_dir_chain(target.parent, owners, "output")
    directory = target.parent
    tmp = directory / f".{target.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode)
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, target)
    except OSError as error:
        refuse("worker_failed", f"cannot write {target}: {error.strerror}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    fsync_directory(directory)


def ensure_dir(path, mode, test_mode=False, owners=None, gid=None):
    target = absolute(path)
    if owners is None:
        owners = {0, os.geteuid()} if test_mode else {0}
    check_dir_chain(target.parent, owners, "directory")
    info = lstat_or_none(target)
    if info is None:
        try:
            os.makedirs(target, mode=mode, exist_ok=True)
        except OSError as error:
            refuse("worker_failed", f"cannot create directory {target}: {error.strerror}")
        info = lstat_or_none(target)
    if info is None or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        refuse("configuration_invalid", f"unsafe directory: {target}")
    if info.st_mode & 0o022:
        refuse("configuration_invalid", f"directory is writable by group/other: {target}")
    if info.st_uid not in owners:
        refuse("configuration_invalid", f"directory has an unexpected owner: {target}")
    try:
        if (info.st_mode & 0o777) != mode:
            os.chmod(target, mode)
        if os.geteuid() == 0 and gid is not None and info.st_gid != gid:
            os.chown(target, 0, gid)
    except OSError as error:
        refuse("worker_failed", f"cannot set directory metadata on {target}: {error.strerror}")
    return target


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def canonical_url(value, protocols, label):
    if not isinstance(value, str) or not value.strip():
        refuse("configuration_invalid", f"{label} must be a non-empty absolute URL")
    try:
        parsed = urllib.parse.urlsplit(value.strip())
    except ValueError:
        refuse("configuration_invalid", f"{label} is not a valid URL")
    scheme = parsed.scheme.lower()
    if scheme not in protocols:
        refuse(
            "configuration_invalid",
            f"{label} must use one of: {', '.join(sorted(protocols))}",
        )
    if parsed.username or parsed.password:
        refuse("configuration_invalid", f"{label} must not embed credentials")
    if parsed.fragment:
        refuse("configuration_invalid", f"{label} must not include a fragment")
    host = (parsed.hostname or "").lower()
    if not host:
        refuse("configuration_invalid", f"{label} must include a host")
    try:
        port = parsed.port
    except ValueError:
        refuse("configuration_invalid", f"{label} has an invalid port")
    default = {"ws": 80, "wss": 443, "http": 80, "https": 443}[scheme]
    if ":" in host:
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None and port != default:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))


def plain_ip(value, label):
    text = str(value).strip()
    if "/" in text:
        refuse("configuration_invalid", f"{label} must be a plain IP, not a CIDR block")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        refuse("configuration_invalid", f"{label} is not an IP address")


def normalize_media(entries, label):
    if not isinstance(entries, list):
        refuse("configuration_invalid", f"{label} must be an array")
    if len(entries) > 16:
        refuse("configuration_invalid", f"{label} accepts at most 16 entries")
    result = []
    for entry in entries:
        if not isinstance(entry, str):
            refuse("configuration_invalid", f"{label} entries must be strings")
        address = plain_ip(entry, f"{label} entry")
        if address not in result:
            result.append(address)
    return sorted(result)


def routing_fingerprint(ws_url, api_url, media_ips, approval):
    """SHA-256 of the canonical routing identity pinned by the operator."""
    document = {
        "wsURL": ws_url,
        "apiURL": api_url,
        "mediaIps": sorted(media_ips),
        "approval": approval,
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def record_approval(record):
    management = record.get("management")
    if management is None:
        return "unmanaged"
    return str(management.get("approvalStatus") or "")


def record_fingerprint(record):
    try:
        ws_url = canonical_url(record.get("wsURL"), {"ws", "wss"}, "dashboard wsURL")
        api_url = canonical_url(record.get("apiURL"), {"http", "https"}, "dashboard apiURL")
        media = normalize_media(record.get("mediaIps") or [], "dashboard mediaIps")
        return routing_fingerprint(ws_url, api_url, media, record_approval(record))
    except Refusal:
        return None


def compare_identity(pin, record):
    """Return an allowlisted reason when the dashboard record drifted from pins."""
    try:
        ws_url = canonical_url(record.get("wsURL"), {"ws", "wss"}, "dashboard wsURL")
        api_url = canonical_url(record.get("apiURL"), {"http", "https"}, "dashboard apiURL")
        media = normalize_media(record.get("mediaIps") or [], "dashboard mediaIps")
    except Refusal:
        return "identity_mismatch"
    if ws_url != pin["wsURL"] or api_url != pin["apiURL"] or media != pin["mediaIps"]:
        return "identity_mismatch"

    approval = record_approval(record)
    if pin["approval"] == "unmanaged":
        if approval != "unmanaged":
            return "identity_mismatch"
        return None
    # pin expects a managed, approved record
    if approval != "approved":
        return "approval_required"
    return None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def resolve_service_account(name):
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return None, None
    return entry.pw_uid, entry.pw_gid


def trusted_owners(test_mode):
    return {0, os.geteuid()} if test_mode else {0}


def validate_helper(path, label, test_mode, executable=False):
    """Validate a bundled helper: root-owned, immutable, inside the bundle."""
    owners = trusted_owners(test_mode)
    info = check_file(path, label, owners, executable=executable)
    real = Path(os.path.realpath(str(path)))
    if not test_mode:
        bundle = Path(os.path.realpath(str(TRUSTED_BUNDLE)))
        if not real.is_relative_to(bundle):
            refuse(
                "configuration_invalid",
                f"{label} must live in the root-owned bundle {bundle}",
            )
        check_dir_chain(bundle, {0}, "bundle")
    if info.st_size > 4 * 1024 * 1024:
        refuse("configuration_invalid", f"{label} is unexpectedly large: {path}")
    return real


def load_runtime_public_host(path):
    """Read GATEWAY_PUBLIC_HOST from the root-private runtime env file."""
    try:
        text = read_regular(path, "runtime environment file").decode("utf-8")
    except UnicodeDecodeError:
        refuse("configuration_invalid", "runtime environment file is not valid UTF-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            refuse("configuration_invalid", "runtime environment file is not KEY=VALUE")
        key, value = stripped.split("=", 1)
        if key.strip() == "GATEWAY_PUBLIC_HOST":
            host = value.strip().strip("'\"")
            if len(host) > 253 or not HOST_RE.match(host) or ".." in host:
                refuse("configuration_invalid", "GATEWAY_PUBLIC_HOST is not a valid hostname")
            return host
    refuse("configuration_invalid", "runtime environment file does not set GATEWAY_PUBLIC_HOST")


def load_config(path, test_mode):
    owners = trusted_owners(test_mode)
    info = check_file(path, "worker config", owners, private=True)
    if info.st_size > 1024 * 1024:
        refuse("configuration_invalid", "worker config is unexpectedly large")
    try:
        data = json.loads(read_regular(path, "worker config").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("configuration_invalid", "worker config is not valid UTF-8 JSON")
    if not isinstance(data, dict):
        refuse("configuration_invalid", "worker config must be a JSON object")
    if data.get("schemaVersion") != CONFIG_SCHEMA_VERSION:
        refuse("configuration_invalid", "worker config schemaVersion must be 1")

    allowed = {"schemaVersion", "lockDir", "statusFile", "controlFile", "runtime",
               "firewallAdapter", "pbx"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        refuse("configuration_invalid", f"unsupported worker config field(s): {', '.join(unknown)}")

    runtime = data.get("runtime")
    if not isinstance(runtime, dict):
        refuse("configuration_invalid", 'worker config field "runtime" must be an object')
    runtime_allowed = {"syncScript", "envFile", "gatewayUrl", "stateDir", "turnRoot",
                       "unitDir", "iface", "serviceUser"}
    unknown = sorted(set(runtime) - runtime_allowed)
    if unknown:
        refuse("configuration_invalid", f"unsupported runtime field(s): {', '.join(unknown)}")
    for key in ("syncScript", "envFile", "gatewayUrl"):
        if not isinstance(runtime.get(key), str) or not runtime[key].strip():
            refuse("configuration_invalid", f"runtime.{key} is required")

    service_user = runtime.get("serviceUser", DEFAULT_SERVICE_USER)
    if not isinstance(service_user, str) or not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", service_user):
        refuse("configuration_invalid", "runtime.serviceUser is not a valid account name")
    iface = runtime.get("iface", DEFAULT_IFACE)
    if not isinstance(iface, str) or not IFACE_RE.match(iface):
        refuse("configuration_invalid", "runtime.iface is not a valid interface name")

    def path_field(value, label, default):
        if value is None:
            value = default
        if not isinstance(value, str) or not value.startswith("/"):
            refuse("configuration_invalid", f"{label} must be an absolute path")
        return absolute(value)

    service_uid, service_gid = resolve_service_account(service_user)
    if not test_mode and service_uid is None:
        refuse("configuration_invalid", f"service account {service_user} does not exist")

    config = {
        "testMode": test_mode,
        "configFile": absolute(path),
        "lockDir": path_field(data.get("lockDir"), "lockDir", DEFAULT_LOCK_DIR),
        "statusFile": path_field(data.get("statusFile"), "statusFile", DEFAULT_STATUS_FILE),
        "controlFile": path_field(data.get("controlFile"), "controlFile", DEFAULT_CONTROL_FILE),
        "syncScript": path_field(runtime.get("syncScript"), "runtime.syncScript", None),
        "envFile": path_field(runtime.get("envFile"), "runtime.envFile", None),
        "gatewayUrl": canonical_url(runtime.get("gatewayUrl"), {"http", "https"},
                                    "runtime.gatewayUrl").rstrip("/"),
        "stateDir": path_field(runtime.get("stateDir"), "runtime.stateDir", DEFAULT_STATE_DIR),
        "turnRoot": path_field(runtime.get("turnRoot"), "runtime.turnRoot", DEFAULT_TURN_ROOT),
        "unitDir": path_field(runtime.get("unitDir"), "runtime.unitDir", DEFAULT_UNIT_DIR),
        "iface": iface,
        "serviceUser": service_user,
        "serviceUid": service_uid,
        "serviceGid": service_gid,
        "firewallAdapter": None,
        "pbx": {},
    }
    if os.path.basename(config["statusFile"]) == "control.json":
        refuse("configuration_invalid", "statusFile must never be control.json")
    if config["statusFile"] == config["controlFile"]:
        refuse("configuration_invalid", "statusFile must not be the control store")

    adapter = data.get("firewallAdapter")
    if adapter is not None:
        if not isinstance(adapter, str) or not adapter.startswith("/"):
            refuse("configuration_invalid", "firewallAdapter must be an absolute path")
        config["firewallAdapter"] = validate_helper(
            adapter, "firewall adapter", test_mode, executable=True
        )

    validate_helper(config["syncScript"], "sync script", test_mode)
    check_file(config["envFile"], "runtime environment file", trusted_owners(test_mode), private=True)
    config["publicHost"] = load_runtime_public_host(config["envFile"])

    pins = data.get("pbx")
    if not isinstance(pins, dict):
        refuse("configuration_invalid", 'worker config field "pbx" must be an object')
    if len(pins) > 128:
        refuse("configuration_invalid", "worker config pins too many PBX records")
    for pbx_id, entry in pins.items():
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id):
            refuse("configuration_invalid", f"worker config has an invalid PBX id: {pbx_id!r}")
        if not isinstance(entry, dict):
            refuse("configuration_invalid", f"pin for {pbx_id} must be an object")
        allowed_keys = {"wsURL", "apiURL", "mediaIps", "approval", "fingerprint", "hookAdapter"}
        unknown = sorted(set(entry) - allowed_keys)
        if unknown:
            refuse("configuration_invalid", f"pin for {pbx_id} has unsupported field(s): {', '.join(unknown)}")
        ws_url = canonical_url(entry.get("wsURL"), {"ws", "wss"}, f"{pbx_id} wsURL")
        api_url = canonical_url(entry.get("apiURL"), {"http", "https"}, f"{pbx_id} apiURL")
        media = normalize_media(entry.get("mediaIps"), f"{pbx_id} mediaIps")
        approval = entry.get("approval")
        if approval not in APPROVALS:
            refuse("configuration_invalid", f"pin for {pbx_id} approval must be 'approved' or 'unmanaged'")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not SHA256_RE.match(fingerprint):
            refuse("configuration_invalid", f"pin for {pbx_id} fingerprint must be a lowercase sha256")
        expected = routing_fingerprint(ws_url, api_url, media, approval)
        if expected != fingerprint:
            refuse(
                "configuration_invalid",
                f"pin fingerprint for {pbx_id} does not match its pinned routing fields",
            )
        hook_adapter = entry.get("hookAdapter")
        if hook_adapter is not None:
            if not isinstance(hook_adapter, str) or not hook_adapter.startswith("/"):
                refuse("configuration_invalid", f"pin for {pbx_id} hookAdapter must be an absolute path")
            hook_adapter = validate_helper(
                hook_adapter, f"hook adapter for {pbx_id}", test_mode, executable=True
            )
        config["pbx"][pbx_id] = {
            "wsURL": ws_url,
            "apiURL": api_url,
            "mediaIps": media,
            "approval": approval,
            "fingerprint": fingerprint,
            "hookAdapter": hook_adapter,
        }
    return config


def load_control(config):
    owners = trusted_owners(config["testMode"])
    if config["serviceUid"] is not None:
        owners.add(config["serviceUid"])
    info = check_file(config["controlFile"], "control store", owners, private=True)
    if info.st_size > 32 * 1024 * 1024:
        refuse("configuration_invalid", "control store is unexpectedly large")
    raw = read_regular(config["controlFile"], "control store")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("configuration_invalid", "control store is not valid UTF-8 JSON")
    if not isinstance(data, dict):
        refuse("configuration_invalid", "control store must be a JSON object")
    version = data.get("schemaVersion", data.get("version"))
    if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > 2:
        refuse("configuration_invalid", "control store has an unsupported schema version")
    records = data.get("pbx", [])
    if not isinstance(records, list):
        refuse("configuration_invalid", 'control store field "pbx" must be an array')
    parsed = {}
    for record in records:
        if not isinstance(record, dict):
            refuse("configuration_invalid", "control store contains an invalid PBX record")
        pbx_id = record.get("id")
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id):
            refuse("configuration_invalid", "control store contains an invalid PBX id")
        if pbx_id in parsed:
            refuse("configuration_invalid", f"control store contains duplicate PBX id {pbx_id}")
        name = record.get("name")
        if not isinstance(name, str) or not name.strip():
            refuse("configuration_invalid", f"control store PBX {pbx_id} has no name")
        if not isinstance(record.get("enabled"), bool):
            refuse("configuration_invalid", f"control store PBX {pbx_id} enabled must be boolean")
        for key in ("wsURL", "apiURL"):
            if not isinstance(record.get(key), str):
                refuse("configuration_invalid", f"control store PBX {pbx_id} {key} must be a string")
        media = record.get("mediaIps", [])
        if not isinstance(media, list) or any(not isinstance(entry, str) for entry in media):
            refuse("configuration_invalid", f"control store PBX {pbx_id} mediaIps must be a string array")
        management = record.get("management")
        if management is not None:
            if not isinstance(management, dict):
                refuse("configuration_invalid", f"control store PBX {pbx_id} management must be an object")
            if not isinstance(management.get("approvalStatus"), str):
                refuse("configuration_invalid", f"control store PBX {pbx_id} management approvalStatus is missing")
        parsed[pbx_id] = {
            "id": pbx_id,
            "name": name.strip(),
            "enabled": record["enabled"],
            "wsURL": record["wsURL"],
            "apiURL": record["apiURL"],
            "mediaIps": list(media),
            "management": management,
            "updatedAt": record.get("updatedAt") if isinstance(record.get("updatedAt"), str) else None,
        }
    return parsed, digest


def load_plan(config):
    owners = trusted_owners(config["testMode"])
    if config["serviceUid"] is not None:
        owners.add(config["serviceUid"])
    path = config["stateDir"] / "tenant-plan.json"
    info = check_file(path, "allocation plan", owners, private=True, must_exist=False)
    if info is None:
        return {}
    try:
        data = json.loads(read_regular(path, "allocation plan").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("configuration_invalid", "allocation plan is not valid UTF-8 JSON")
    if not isinstance(data, dict) or data.get("schemaVersion") != 1:
        refuse("configuration_invalid", "allocation plan has an unsupported schema")
    allocations = data.get("allocations")
    if not isinstance(allocations, dict):
        refuse("configuration_invalid", 'allocation plan field "allocations" must be an object')
    parsed = {}
    slots = {}
    slugs = {}
    ports = {}
    for pbx_id, entry in allocations.items():
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id):
            refuse("configuration_invalid", "allocation plan has an invalid PBX id")
        if not isinstance(entry, dict):
            refuse("configuration_invalid", f"allocation plan entry for {pbx_id} is invalid")
        slug = entry.get("slug")
        if not isinstance(slug, str) or not SLUG_RE.match(slug):
            refuse("configuration_invalid", f"allocation plan slug for {pbx_id} is invalid")
        base = re.sub(r"[^a-z0-9]+", "-", pbx_id.lower()).strip("-")[:19].strip("-")
        digest = hashlib.sha256(pbx_id.encode("utf-8")).hexdigest()[:8]
        allowed_slugs = {base} if base else set()
        if base:
            allowed_slugs.add(f"{base[:10]}-{digest}")
        if slug not in allowed_slugs:
            refuse(
                "configuration_invalid",
                f"allocation plan slug for {pbx_id} is not derivable from its PBX id",
            )
        slot = entry.get("slot")
        if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < MAX_SLOTS:
            refuse("configuration_invalid", f"allocation plan slot for {pbx_id} is invalid")
        listener = LISTENER_BASE + slot
        relay_min = RELAY_BASE + slot * RELAY_SPAN
        relay_max = relay_min + RELAY_SPAN - 1
        if listener in RESERVED_LISTENER_PORTS:
            refuse("configuration_invalid", f"allocation plan slot for {pbx_id} is reserved")
        if (entry.get("listenerPort"), entry.get("relayMinPort"), entry.get("relayMaxPort")) != (
            listener, relay_min, relay_max,
        ):
            refuse(
                "configuration_invalid",
                f"allocation plan ports for {pbx_id} do not match their slot",
            )
        if slot in slots:
            refuse("configuration_invalid", f"allocation plan reuses slot {slot}")
        slots[slot] = pbx_id
        if slug in slugs:
            refuse("configuration_invalid", f"allocation plan reuses slug {slug}")
        slugs[slug] = pbx_id
        if listener in ports:
            refuse("configuration_invalid", f"allocation plan reuses port {listener}")
        ports[listener] = pbx_id
        peers = entry.get("peerIps", [])
        if not isinstance(peers, list):
            refuse("configuration_invalid", f"allocation plan peerIps for {pbx_id} must be an array")
        clean_peers = []
        for peer in peers:
            if not isinstance(peer, str):
                refuse("configuration_invalid", f"allocation plan peerIps for {pbx_id} is invalid")
            address = plain_ip(peer, f"allocation plan peerIps for {pbx_id}")
            if address not in clean_peers:
                clean_peers.append(address)
        parsed[pbx_id] = {"slug": slug, "listenerPort": listener,
                          "relayMinPort": relay_min, "relayMaxPort": relay_max,
                          "peerIps": clean_peers}
    return parsed


def load_manifest(config):
    owners = trusted_owners(config["testMode"])
    if config["serviceUid"] is not None:
        owners.add(config["serviceUid"])
    path = config["stateDir"] / "tenant-runtime.json"
    info = check_file(path, "runtime manifest", owners, private=True, must_exist=False)
    if info is None:
        return None
    try:
        data = json.loads(read_regular(path, "runtime manifest").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("relays"), dict):
        return None
    return data


def load_tokens(config):
    owners = trusted_owners(config["testMode"])
    # The token file lives beside the control store in the state directory, which
    # the service account owns. It is trusted exactly like the plan, the runtime
    # manifest and the control store; without this the state directory would
    # have to be root-owned, which the control service cannot write to.
    if config["serviceUid"] is not None:
        owners.add(config["serviceUid"])
    path = config["stateDir"] / "hook-tokens.json"
    info = check_file(path, "hook token file", owners, private=True, must_exist=False)
    if info is None:
        return {}
    try:
        data = json.loads(read_regular(path, "hook token file").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    tokens = {}
    for pbx_id, token in data.items():
        if isinstance(pbx_id, str) and PBX_ID_RE.match(pbx_id) and isinstance(token, str) and TOKEN_RE.match(token):
            tokens[pbx_id] = token
    return tokens


def read_control_digest(config):
    """Hash the dashboard control bytes so privileged stages can detect edits."""
    owners = trusted_owners(config["testMode"])
    if config["serviceUid"] is not None:
        owners.add(config["serviceUid"])
    check_file(config["controlFile"], "control store", owners, private=True)
    return hashlib.sha256(read_regular(config["controlFile"], "control store")).hexdigest()


def ensure_control_unchanged(config, expected):
    try:
        current = read_control_digest(config)
    except Refusal:
        raise ControlChanged() from None
    if current != expected:
        raise ControlChanged()


def load_previous_status(config):
    """Previous sanitized status, trusted only when root-owned and immutable.

    A status file inside a service-writable directory can be renamed/replaced by
    the service user, so it is never trusted for skip decisions. It is only a
    cache hint: a skipped run still re-verifies the root-owned unit, the manifest
    and the private relay secret.
    """
    path = config["statusFile"]
    info = lstat_or_none(path)
    if info is None or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return {}
    allowed_owners = {0} if not config["testMode"] else {0, os.geteuid()}
    if info.st_uid not in allowed_owners or info.st_mode & 0o007:
        return {}
    try:
        check_dir_chain(path.parent, {0, os.geteuid()} if config["testMode"] else {0}, "status")
    except Refusal:
        return {}
    try:
        data = json.loads(read_regular(path, "previous status").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict) or data.get("schemaVersion") != STATUS_SCHEMA_VERSION:
        return {}
    entries = data.get("pbx")
    if not isinstance(entries, dict):
        return {}
    clean = {}
    for pbx_id, entry in entries.items():
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id) or not isinstance(entry, dict):
            continue
        state = entry.get("state")
        reason = entry.get("reason")
        fingerprint = entry.get("fingerprint")
        stages = entry.get("stages")
        if state not in STATES or reason not in REASONS:
            continue
        if not isinstance(stages, dict) or any(stages.get(key) not in STAGE_VALUES
                                              for key in ("relay", "firewall", "hook")):
            continue
        if fingerprint is not None and (not isinstance(fingerprint, str) or not SHA256_RE.match(fingerprint)):
            continue
        clean[pbx_id] = {"state": state, "reason": reason,
                         "stages": {key: stages[key] for key in ("relay", "firewall", "hook")},
                         "fingerprint": fingerprint,
                         "capturedUpdatedAt": entry.get("capturedUpdatedAt")
                         if isinstance(entry.get("capturedUpdatedAt"), str) else None}
    return clean


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(config):
    records, control_digest = load_control(config)
    allocations = load_plan(config)
    entries = {}
    ids = sorted(set(config["pbx"]) | set(records) | set(allocations))
    global_reason = None

    for pbx_id in ids:
        pin = config["pbx"].get(pbx_id)
        record = records.get(pbx_id)
        allocation = allocations.get(pbx_id)
        fingerprint = record_fingerprint(record) if record is not None else None
        if fingerprint is None and pin is not None:
            fingerprint = pin["fingerprint"]

        reason = None
        kind = "blocked"
        if pin is None:
            reason = "not_configured"
        elif record is None:
            reason = "not_configured"
        else:
            mismatch = compare_identity(pin, record)
            if mismatch:
                reason = mismatch
            elif record["enabled"]:
                if not pin["mediaIps"]:
                    reason = "not_configured"
                elif config["firewallAdapter"] is None:
                    reason = "firewall_required"
                elif pin["hookAdapter"] is None:
                    reason = "hook_required"
                else:
                    kind = "eligible"
            else:
                kind = "disabled"

        if reason is not None and allocation is not None and record is not None and global_reason is None:
            # A retired PBX (no control record) keeps its allocation slot on
            # purpose: slots are never reused, and the sync tears the relay
            # down (unit stopped, manifest entry dropped) for exactly that
            # case. Only a live record whose pin is missing or drifted is a
            # real drift that must stop the whole run before anything is
            # touched.
            global_reason = reason
        entries[pbx_id] = {
            "kind": kind,
            "reason": reason,
            "pin": pin,
            "record": record,
            "allocation": allocation,
            "fingerprint": fingerprint,
        }
    return {"config": config, "records": records, "allocations": allocations,
            "entries": entries, "globalReason": global_reason,
            "controlDigest": control_digest}


def build_snapshot(entries):
    snapshot = []
    for pbx_id in sorted(entries):
        entry = entries[pbx_id]
        if entry["kind"] not in ("eligible", "disabled"):
            continue
        record = entry["record"]
        snapshot.append({
            "id": record["id"],
            "name": record["name"],
            "wsURL": record["wsURL"],
            "apiURL": record["apiURL"],
            "mediaIps": list(record["mediaIps"]),
            "enabled": record["enabled"],
        })
    return snapshot


def captured_updated_at(entry):
    record = entry.get("record")
    return record.get("updatedAt") if record else None


def status_entry(state, reason, relay="skipped", firewall="skipped", hook="skipped",
                 fingerprint=None, captured=None):
    assert state in STATES and reason in REASONS
    assert relay in STAGE_VALUES and firewall in STAGE_VALUES and hook in STAGE_VALUES
    return {
        "state": state,
        "stages": {"relay": relay, "firewall": firewall, "hook": hook},
        "reason": reason,
        "fingerprint": fingerprint,
        "capturedUpdatedAt": captured,
    }


def blocked_status(entries, global_reason, previous=None):
    """Every PBX is blocked; the offender keeps its specific reason."""
    previous = previous or {}
    result = {}
    for pbx_id in sorted(entries):
        entry = entries[pbx_id]
        reason = entry["reason"] or global_reason or "not_configured"
        if entry["reason"] is None and global_reason is not None:
            prior = previous.get(pbx_id)
            reason = "stale" if prior and prior.get("state") == "ready" else "not_configured"
        result[pbx_id] = status_entry(
            "blocked", reason,
            relay="blocked", firewall="blocked", hook="blocked",
            fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
        )
    return result


def planned_status(entries):
    result = {}
    for pbx_id in sorted(entries):
        entry = entries[pbx_id]
        if entry["kind"] == "eligible":
            result[pbx_id] = status_entry(
                "planned", "planned", relay="planned", firewall="planned", hook="planned",
                fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
            )
        elif entry["kind"] == "disabled":
            result[pbx_id] = status_entry(
                "blocked", "not_configured", relay="skipped", firewall="skipped", hook="skipped",
                fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
            )
        else:
            result[pbx_id] = status_entry(
                "blocked", entry["reason"], relay="blocked", firewall="blocked", hook="blocked",
                fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
            )
    return result


def abort_status(state):
    """Status for an aborted run: never leave a previous ready result visible."""
    if state is None:
        return status_document({})
    result = {}
    for pbx_id, entry in sorted(state["entries"].items()):
        result[pbx_id] = status_entry(
            "error", "worker_failed", relay="pending", firewall="pending", hook="pending",
            fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
        )
    return status_document(result)


# ---------------------------------------------------------------------------
# Commands (never a shell; output suppressed for adapters)
# ---------------------------------------------------------------------------


def minimal_env():
    return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def systemctl_path(test_mode):
    if test_mode:
        override = os.environ.get("PROVISIONING_TEST_SYSTEMCTL")
        if override:
            return override
    for candidate in ("/usr/bin/systemctl", "/bin/systemctl"):
        if os.path.exists(candidate):
            return candidate
    return None


def unit_active(unit, test_mode):
    executable = systemctl_path(test_mode)
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [executable, "is-active", unit],
            check=False, capture_output=True, text=True,
            timeout=SYSTEMCTL_TIMEOUT, env=minimal_env(), shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and (result.stdout or "").strip() == "active"


def run_sync(config, snapshot):
    """Run the reviewed sync script with a root-private filtered snapshot."""
    lock_dir = config["lockDir"]
    snapshot_path = lock_dir / "control.snapshot.json"
    payload = json.dumps({"schemaVersion": 2, "pbx": snapshot}, indent=2, sort_keys=True) + "\n"
    atomic_write(snapshot_path, payload, 0o600, test_mode=config["testMode"])
    argv = [
        sys.executable,
        str(config["syncScript"]),
        "--control", str(snapshot_path),
        "--state-dir", str(config["stateDir"]),
        "--turn-root", str(config["turnRoot"]),
        "--unit-dir", str(config["unitDir"]),
        "--iface", config["iface"],
        "--service-user", config["serviceUser"],
        "--env-file", str(config["envFile"]),
        "--json",
    ]
    try:
        result = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=minimal_env(),
            shell=False,
        )
    except OSError:
        try:
            snapshot_path.unlink()
        except OSError:
            pass
        return False, False
    try:
        try:
            output, _ = result.communicate(timeout=SYNC_TIMEOUT)
        except subprocess.TimeoutExpired:
            result.kill()
            result.communicate()
            return False, False
        finally:
            try:
                snapshot_path.unlink()
            except OSError:
                pass
        if result.returncode not in (0, 1):
            return False, False
        if output is None or len(output) > MAX_SYNC_OUTPUT:
            return False, False
        try:
            document = json.loads(output)
        except json.JSONDecodeError:
            return False, False
        warnings = document.get("warnings") if isinstance(document, dict) else None
        if not isinstance(warnings, list):
            return False, False
        return True, bool(warnings) or result.returncode == 1
    finally:
        if result.poll() is None:
            result.kill()
            result.wait()


def call_adapter(executable, pbx_id, request):
    """Invoke a trusted adapter. Its output is discarded, never buffered/logged."""
    try:
        result = subprocess.run(
            [str(executable), pbx_id],
            input=json.dumps(request, sort_keys=True),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=ADAPTER_TIMEOUT,
            env=minimal_env(),
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def firewall_request(config, pbx_id, allocation, enabled, peers=None):
    return {
        "pbxId": pbx_id,
        "gatewayUrl": config["gatewayUrl"],
        "listenerPort": allocation["listenerPort"],
        "peerIps": list(peers if peers is not None else allocation["peerIps"]),
        "enabled": enabled,
    }


def hook_request(config, pbx_id, allocation, token, peers=None, retired=None):
    return {
        "pbxId": pbx_id,
        "gatewayUrl": config["gatewayUrl"],
        "listenerPort": allocation["listenerPort"],
        "peerIps": list(peers if peers is not None else allocation["peerIps"]),
        "enabled": True,
        "token": token,
        # PBX ids removed from the dashboard. Their push-hook configuration on
        # the PBX is stale and may be replaced; a configuration that belongs to
        # a live PBX never is.
        "retiredPbxIds": list(retired or []),
    }


def relay_verified(entry, allocations, manifest, tokens, config):
    """Ready evidence: pinned manifest identity, private secret and live unit."""
    record = entry["record"]
    if record is None or not record["enabled"]:
        return False
    pbx_id = record["id"]
    allocation = allocations.get(pbx_id)
    if allocation is None or manifest is None:
        return False
    relay = manifest.get("relays", {}).get(pbx_id)
    if not isinstance(relay, dict):
        return False
    if relay.get("host") != config["publicHost"]:
        return False
    if relay.get("port") != allocation["listenerPort"]:
        return False
    peers = relay.get("peerIps")
    if not isinstance(peers, list):
        return False
    try:
        if normalize_media(peers, "manifest peerIps") != entry["pin"]["mediaIps"]:
            return False
    except Refusal:
        return False

    expected_secret = config["stateDir"] / "secrets" / f"{allocation['slug']}.secret"
    if relay.get("secretFile") != str(expected_secret):
        return False
    owners = trusted_owners(config["testMode"])
    if config["serviceUid"] is not None:
        owners.add(config["serviceUid"])
    try:
        check_file(expected_secret, "relay secret", owners, private=True)
    except Refusal:
        return False

    token = tokens.get(pbx_id)
    if token is None:
        return False
    hook_hash = manifest.get("hookHashes", {}).get(pbx_id)
    if hook_hash != hashlib.sha256(token.encode("utf-8")).hexdigest():
        return False

    unit = UNIT_TEMPLATE.replace("@.service", f"@{allocation['slug']}.service")
    return unit_active(unit, config["testMode"])


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def disabled_settled(_entry, previous):
    if not previous or previous.get("state") != "blocked":
        return False
    stages = previous.get("stages") or {}
    return stages.get("relay") == "skipped"


def apply_run(state, previous):
    config = state["config"]
    entries = state["entries"]
    eligible = [pbx_id for pbx_id, entry in entries.items() if entry["kind"] == "eligible"]
    disabled = [pbx_id for pbx_id, entry in entries.items() if entry["kind"] == "disabled"]
    state.setdefault("tokens", load_tokens(config))
    state.setdefault("manifest", load_manifest(config))

    def guard():
        # Any dashboard edit (endpoint, media, approval, even an audit entry)
        # aborts before the next privileged stage; nothing is reported ready
        # from a record that changed underneath the run.
        ensure_control_unchanged(config, state["controlDigest"])

    def skip_ready(pbx_id):
        prior = previous.get(pbx_id)
        entry = entries[pbx_id]
        if not prior or prior.get("state") != "ready":
            return False
        if prior.get("fingerprint") != entry["fingerprint"]:
            return False
        if any(prior["stages"].get(key) != "ready" for key in ("relay", "firewall", "hook")):
            return False
        return relay_verified(entry, state["allocations"], state["manifest"],
                              state["tokens"], config)

    need_sync = any(not skip_ready(pbx_id) for pbx_id in eligible)
    if not need_sync:
        for pbx_id in disabled:
            if entries[pbx_id]["allocation"] is None:
                continue
            if not disabled_settled(entries[pbx_id], previous.get(pbx_id)):
                need_sync = True
                break

    result = {}
    if need_sync:
        guard()
        snapshot = build_snapshot(entries)
        ok, degraded = run_sync(config, snapshot)
        if not ok or degraded:
            for pbx_id in eligible + disabled:
                result[pbx_id] = status_entry(
                    "error", "relay_failed", relay="error", firewall="skipped", hook="skipped",
                    fingerprint=entries[pbx_id]["fingerprint"],
                    captured=captured_updated_at(entries[pbx_id]),
                )
            return result
        state["allocations"] = load_plan(config)
        state["manifest"] = load_manifest(config)
        state["tokens"] = load_tokens(config)
    else:
        state["tokens"] = load_tokens(config)

    allocations = state["allocations"]
    manifest = state["manifest"]
    tokens = state["tokens"]

    # PBX ids that were removed from the dashboard: their relay allocation is
    # retained on purpose, so their push-hook configuration on the PBX is stale.
    retired = sorted(
        other for other, other_entry in entries.items()
        if other_entry["record"] is None and other_entry["allocation"] is not None
    )
    for pbx_id in eligible:
        entry = entries[pbx_id]
        fingerprint = entry["fingerprint"]
        captured = captured_updated_at(entry)
        guard()
        if skip_ready(pbx_id):
            result[pbx_id] = status_entry("ready", "ready", relay="ready", firewall="ready",
                                          hook="ready", fingerprint=fingerprint, captured=captured)
            continue
        if not relay_verified(entry, allocations, manifest, tokens, config):
            result[pbx_id] = status_entry("error", "relay_failed", relay="error",
                                          firewall="skipped", hook="skipped",
                                          fingerprint=fingerprint, captured=captured)
            continue
        allocation = allocations[pbx_id]
        guard()
        if not call_adapter(config["firewallAdapter"], pbx_id,
                            firewall_request(config, pbx_id, allocation, True,
                                             peers=entry["pin"]["mediaIps"])):
            result[pbx_id] = status_entry("error", "firewall_failed", relay="ready",
                                          firewall="error", hook="skipped",
                                          fingerprint=fingerprint, captured=captured)
            continue
        token = tokens.get(pbx_id)
        if token is None:
            result[pbx_id] = status_entry("blocked", "hook_required", relay="ready",
                                          firewall="ready", hook="blocked",
                                          fingerprint=fingerprint, captured=captured)
            continue
        guard()
        if not call_adapter(entry["pin"]["hookAdapter"], pbx_id,
                            hook_request(config, pbx_id, allocation, token,
                                         peers=entry["pin"]["mediaIps"], retired=retired)):
            result[pbx_id] = status_entry("error", "hook_failed", relay="ready",
                                          firewall="ready", hook="error",
                                          fingerprint=fingerprint, captured=captured)
            continue
        guard()
        result[pbx_id] = status_entry("ready", "ready", relay="ready", firewall="ready",
                                      hook="ready", fingerprint=fingerprint, captured=captured)

    for pbx_id in disabled:
        # Disabled records are passed to sync as enabled=false (stop unit, remove
        # ufw rules, remove service secret copy). Cloud firewall policy is
        # intentionally retained: the provider adapter is additive, and this
        # worker does not claim to deallocate it. No hook is installed.
        entry = entries[pbx_id]
        result[pbx_id] = status_entry(
            "blocked", "not_configured", relay="skipped", firewall="skipped", hook="skipped",
            fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
        )

    for pbx_id, entry in entries.items():
        if pbx_id in result:
            continue
        result[pbx_id] = status_entry(
            "blocked", entry["reason"] or "not_configured",
            relay="blocked", firewall="blocked", hook="blocked",
            fingerprint=entry["fingerprint"], captured=captured_updated_at(entry),
        )
    return result


# ---------------------------------------------------------------------------
# Status / lock / reporting
# ---------------------------------------------------------------------------


def iso_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_document(entries_by_id):
    return {"schemaVersion": STATUS_SCHEMA_VERSION, "updatedAt": iso_timestamp(),
            "pbx": {pbx_id: entries_by_id[pbx_id] for pbx_id in sorted(entries_by_id)}}


def validate_status_target(config):
    """Reject a service-writable or unsafe status parent before any work."""
    path = config["statusFile"]
    if os.path.basename(path) == "control.json" or path == config["controlFile"]:
        refuse("worker_failed", "refusing to write status over a control store")
    owners = {0}
    if config["testMode"]:
        owners.add(os.geteuid())
    parent = path.parent
    info = lstat_or_none(parent)
    if info is None:
        check_dir_chain(parent.parent, owners, "status")
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        refuse("configuration_invalid", f"status parent is not a directory: {parent}")
    if info.st_mode & 0o022:
        refuse("configuration_invalid", f"status parent is writable by group/other: {parent}")
    if info.st_uid not in owners:
        refuse("configuration_invalid", f"status parent has an unexpected owner: {parent}")
    check_dir_chain(parent, owners, "status")


def write_status(config, document):
    path = config["statusFile"]
    if os.path.basename(path) == "control.json" or path == config["controlFile"]:
        refuse("worker_failed", "refusing to write status over a control store")
    owners = {0}
    if config["testMode"]:
        owners.add(os.geteuid())
    ensure_dir(path.parent, 0o750, test_mode=config["testMode"], owners=owners,
               gid=config["serviceGid"])
    info = lstat_or_none(path)
    if info is not None and stat.S_ISLNK(info.st_mode):
        refuse("worker_failed", f"status file is a symlink: {path}")
    atomic_write(
        path,
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        0o640,
        gid=config["serviceGid"] if config["serviceGid"] is not None else 0,
        test_mode=config["testMode"],
        owners=owners,
    )


def acquire_lock(config):
    """flock-based run lock: released by the kernel even after SIGKILL."""
    directory = ensure_dir(config["lockDir"], 0o700, test_mode=config["testMode"])
    lock_path = directory / "lock"
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | NOFOLLOW, 0o600)
    except OSError as error:
        refuse("worker_failed", f"cannot open lock file: {error.strerror}")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    except OSError as error:
        os.close(descriptor)
        refuse("worker_failed", f"cannot lock: {error.strerror}")
    try:
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()} {iso_timestamp()}\n".encode("utf-8"))
        os.fsync(descriptor)
    except OSError:
        pass
    return descriptor


def release_lock(descriptor):
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(descriptor)
    except OSError:
        pass


def lock_is_held(config):
    """Read-only lock probe for --dry-run (never creates the lock file)."""
    path = config["lockDir"] / "lock"
    try:
        descriptor = os.open(path, os.O_RDONLY | NOFOLLOW)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def emit(document):
    sys.stdout.write(json.dumps(document, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="reconcile-tenant-provisioning.py",
        description="Bounded root-run reconcile of pinned PBX tenant provisioning.",
        epilog="Dry-run is the default. systemd passes --apply.",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help=f"root-private worker config (default {DEFAULT_CONFIG})")
    parser.add_argument("--apply", action="store_true",
                        help="perform the reconcile (root; systemd uses this)")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate and print the plan only (default)")
    parser.add_argument("--allow-unprivileged", action="store_true",
                        help="staging/tests only: relax root/bundle ownership checks")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.apply and args.dry_run:
        sys.stderr.write("refused: choose either --apply or --dry-run\n")
        return 2
    test_mode = bool(args.allow_unprivileged)
    if args.apply and os.geteuid() != 0 and not test_mode:
        sys.stderr.write("refused: --apply requires root\n")
        return 2

    try:
        if not test_mode:
            # Production authority is the root-owned bundled copy only.
            validate_helper(Path(os.path.realpath(__file__)), "worker", test_mode)
        config = load_config(args.config, test_mode)
        if args.apply:
            validate_status_target(config)
    except Refusal as error:
        sys.stderr.write(f"refused [{error.reason}]: {error}\n")
        return 2

    if args.apply:
        try:
            lock_handle = acquire_lock(config)
        except Refusal as error:
            sys.stderr.write(f"refused [{error.reason}]: {error}\n")
            return 2
        if lock_handle is None:
            sys.stderr.write("refused [worker_failed]: another provisioning run holds the lock\n")
            return 2
    else:
        lock_handle = None
        if lock_is_held(config):
            sys.stderr.write("refused [worker_failed]: another provisioning run holds the lock\n")
            return 2

    state = None
    try:
        state = evaluate(config)
        if state["globalReason"] is not None:
            previous = load_previous_status(config) if args.apply else {}
            document = status_document(blocked_status(state["entries"], state["globalReason"], previous))
            if args.apply:
                write_status(config, document)
            emit(document)
            sys.stderr.write(
                f"refused [{state['globalReason']}]: provisioning is not authorized for every "
                "existing allocation; no changes were made\n"
            )
            return 2

        if not args.apply:
            document = status_document(planned_status(state["entries"]))
            emit(document)
            return 0

        previous = load_previous_status(config)
        results = apply_run(state, previous)
        # Last gate: never publish a ready result for a record the dashboard
        # edited while adapters were running.
        ensure_control_unchanged(config, state["controlDigest"])
        document = status_document(results)
        write_status(config, document)
        emit(document)
        return 1 if any(entry["state"] == "error" for entry in results.values()) else 0
    except ControlChanged:
        document = abort_status(state)
        if args.apply and state is not None:
            try:
                write_status(config, document)
            except Refusal:
                pass
        emit(document)
        sys.stderr.write(
            "failed [worker_failed]: control store changed during provisioning; "
            "no ready status was reported\n"
        )
        return 1
    except Refusal as error:
        sys.stderr.write(f"refused [{error.reason}]: {error}\n")
        return 2 if error.reason in ("configuration_invalid",) else 1
    except Exception:  # noqa: BLE001 - never leak paths, tokens or adapter output
        if args.apply and state is not None:
            document = abort_status(state)
            try:
                write_status(config, document)
            except Refusal:
                pass
            emit(document)
        sys.stderr.write("failed [worker_failed]: unexpected worker error\n")
        return 1
    finally:
        release_lock(lock_handle)


if __name__ == "__main__":
    sys.exit(main())
