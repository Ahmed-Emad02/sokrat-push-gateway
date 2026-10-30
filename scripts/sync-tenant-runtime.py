#!/usr/bin/env python3
"""Synchronise the per-PBX tenant runtime of the Sokrat push gateway.

WHY
  The gateway can host several customer PBXs. Each PBX needs its own isolated
  TURN relay (own process, own user, own listener port, own relay port range,
  own PBX-only peer ACL) plus its own PBX hook credential. This command derives
  all of that from the private control store, so provisioning is one explicit,
  reviewable operator action instead of hand editing host files.

WHAT IT DOES (run as root on the gateway host)
  1. Reads and validates the private control store
     (/var/lib/sokrat-gateway/control.json): schema version, unique PBX ids,
     real booleans for `enabled`, and plain-IP `mediaIps`.
  2. Allocates one listener port (3500 + slot) and one 100-port relay range
     (50000 + slot*100) per PBX id. The plan is persisted in
     /var/lib/sokrat-gateway/tenant-plan.json and slots are NEVER reused, not
     even after a PBX is disabled or deleted from the control store.
  3. Provisions one isolated coturn instance per ENABLED PBX:
       unit     sokrat-tenant-turn@<slug>.service  (systemd template)
       account  sokrat-turn-<slug>                 (system, nologin, no home)
       config   /etc/sokrat/turn/<slug>/turnserver.conf  (0640 root:<user>)
       secret   /etc/sokrat/turn/<slug>/secret           (0600 root)
     PBX ids contain underscores, which are invalid in systemd instance names
     and in coturn realms, so each id is mapped to a stable lowercase/dash
     slug (collisions get a short deterministic hash suffix).
  4. Publishes what the gateway process may read, and nothing more:
       secret copies  /var/lib/sokrat-gateway/secrets/<slug>.secret
                      (0600 <service user>, e.g. sokrat-push)
       manifest       /var/lib/sokrat-gateway/tenant-runtime.json
                      (0600 <service user>) with the shape consumed by
                      src/tenant-runtime.js / src/tenant-server.js:
                        {"relays": {pbxId: {host, port, secretFile, peerIps}},
                         "hookHashes": {pbxId: sha256(hookToken)}}
  5. Creates one random PBX hook token per PBX on first provision. Only the
     SHA-256 digest reaches the manifest; the plaintext lives solely in the
     root-only file /var/lib/sokrat-gateway/hook-tokens.json (0600). Existing
     tokens are reused so a PBX dialplan never breaks on a re-run. Tokens are
     never printed, logged or echoed.
  6. Disabled (or removed) PBXs: the isolated unit is stopped and disabled, its
     ufw rules and its service-readable secret copy are removed, and it is not
     present in the runtime manifest. The allocation slot, the canonical TURN
     secret and the hook token are retained so re-enabling cannot collide or
     silently rotate credentials.

SAFETY MODEL
  * Two phases: full validation first, then idempotent writes. A refused run
    makes no changes.
  * Refuses: symlinks on or above any managed path, control files that are not
    private regular files (group/other bits set, unexpected owner), corrupt or
    newer-than-supported control schema, duplicate PBX ids, empty/CIDR media
    lists for enabled PBXs, plan files that disagree with their own slot math,
    unmanaged/existing /etc/systemd/system units it did not write, and a config
    root that the unprivileged TURN account cannot traverse (it prints the one
    `chmod o+x` command instead of starting a relay that would fail).
  * Two steps max touch shared state: the coturn template unit and ufw. Nothing
    else outside its own files is modified.
  * No shell interpolation anywhere: every external program is invoked with an
    argv list and no shell. No recursive deletion, no `ufw reset`.
  * Never touches the existing single-PBX coturn on 3478/49160-49260, nginx,
    `.env`, Asterisk/PBX dialplans, endpoint transports or media settings.
  * Do not run this command and `scripts/provision-tenant-relay.py` for the same
    PBX: they use different unit names for the same config directory and would
    both bind the same port. Retire the old `sokrat-turn@<id>` instance first.
  * Secrets are written atomically (temp file + fsync + rename) with the final
    mode applied before the file becomes visible.

USAGE
  # Validate everything and print the exact plan; no host changes, no root.
  ./scripts/sync-tenant-runtime.py --dry-run

  # Apply (root). Environment supplies the deployment addresses.
   sudo GATEWAY_PUBLIC_HOST="$GATEWAY_PUBLIC_HOST" \\
        GATEWAY_LISTEN_IP="$GATEWAY_LISTEN_IP" \\
        GATEWAY_PRIVATE_IP="$GATEWAY_PRIVATE_IP" \\
       ./scripts/sync-tenant-runtime.py

  # Machine-readable plan/summary (never contains secrets).
  sudo ./scripts/sync-tenant-runtime.py --dry-run --json

  # Hosts without ufw (or while validating on a staging box).
  sudo ./scripts/sync-tenant-runtime.py --no-firewall

  # Optional file with the three GATEWAY_* variables (KEY=VALUE, mode 0600).
  sudo ./scripts/sync-tenant-runtime.py --env-file /etc/sokrat/gateway-runtime.env

  The gateway and control services must point at the manifest, for example in
  /etc/sokrat/gateway-control.env:
      TENANT_RUNTIME_FILE=/var/lib/sokrat-gateway/tenant-runtime.json
  Both services run as the same service user, which owns the manifest and the
  secret copies. Restart them after a change (this command does not restart
  the shared gateway: `systemctl restart sokrat-gateway-control` or
  `systemctl restart sokrat-push-gateway` when that unit hosts the runtime).

REQUIRED ENVIRONMENT
  GATEWAY_PUBLIC_HOST   public hostname clients use for TURN (no scheme/port)
  GATEWAY_LISTEN_IP     local address coturn binds its listener to (IPv4)
  GATEWAY_PRIVATE_IP    private/Tailscale address coturn relays from (IPv4)

OPTIONAL ENVIRONMENT / FLAGS
  GATEWAY_CONTROL_FILE  default /var/lib/sokrat-gateway/control.json
  GATEWAY_STATE_DIR     default /var/lib/sokrat-gateway
  GATEWAY_TURN_ROOT     default /etc/sokrat/turn
  GATEWAY_UNIT_DIR      default /etc/systemd/system
  GATEWAY_PRIVATE_IFACE default tailscale0 (peer ACL interface)
  GATEWAY_SERVICE_USER  default sokrat-push
  --control --state-dir --turn-root --unit-dir --iface --service-user
  --dry-run  --json  --no-firewall  --env-file

EXIT CODES
  0  success (or a clean dry run)
  1  applied, but at least one host step reported a warning/failure; the run is
     idempotent, so fix the cause and re-run
  2  refused by validation before any change (or stopped mid-apply; see the
     message: already-completed steps are idempotent)
"""
from __future__ import annotations

import argparse
import datetime
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


CONTROL_SCHEMA_VERSION = 2
PLAN_SCHEMA_VERSION = 1

UNIT_TEMPLATE = "sokrat-tenant-turn@.service"
UNIT_MARKER = "sync-tenant-runtime.py"
CONF_MARKER = "Managed by scripts/sync-tenant-runtime.py"

# Deterministic port plan: listener 3500 + slot, relay 50000 + slot*100.
# MAX_SLOTS is bounded by the 100-port relay spans fitting below 65535 (155).
LISTENER_BASE = 3500
LISTENER_SLOTS = 500
RELAY_BASE = 50000
RELAY_SPAN = 100
MAX_SLOTS = min(LISTENER_SLOTS, (65535 - RELAY_BASE + 1) // RELAY_SPAN)

# Ports owned by other Sokrat services on the gateway; never allocate them.
RESERVED_LISTENER_PORTS = {22, 80, 443, 3478, 8002, 8088, 8095, 9096, 9097}

PBX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,18}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,200}$")
HEX_SECRET_RE = re.compile(r"^[a-f0-9]{64}$")

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class SyncError(Exception):
    """Validation refusal: the run stops before touching the host."""

    def __init__(self, message, code="validation_failed"):
        super().__init__(message)
        self.code = code


def fail(message, code="validation_failed"):
    raise SyncError(message, code)


# ---------------------------------------------------------------------------
# Filesystem helpers (no symlinks, atomic writes, explicit ownership)
# ---------------------------------------------------------------------------


def absolute(path):
    return Path(os.path.abspath(str(path)))


def ensure_no_symlink_ancestors(path):
    """Refuse to operate through any symlinked parent directory."""
    target = absolute(path)
    current = Path(target.parts[0])
    for part in target.parent.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            fail(f"cannot inspect path component {current}: {error}", "path_unsafe")
        if stat.S_ISLNK(info.st_mode):
            fail(f"refusing to operate through symlinked directory {current}", "symlink_refused")
        if not stat.S_ISDIR(info.st_mode):
            fail(f"path component is not a directory: {current}", "path_unsafe")


def check_regular_or_absent(path, label):
    """Return lstat() for a safe regular file, None when absent. Never follows."""
    target = absolute(path)
    ensure_no_symlink_ancestors(target)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        fail(f"cannot inspect {label} {target}: {error}", "path_unsafe")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} is a symlink; refusing to follow it ({target})", "symlink_refused")
    if not stat.S_ISREG(info.st_mode):
        fail(f"{label} is not a regular file ({target})", "path_unsafe")
    return info


def read_regular(path, label):
    info = check_regular_or_absent(path, label)
    if info is None:
        fail(f"{label} not found: {path}", "path_unsafe")
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


def _fchown_if_root(descriptor, uid, gid):
    if os.geteuid() != 0 or uid is None or gid is None:
        return
    try:
        os.fchown(descriptor, uid, gid)
    except OSError as error:
        fail(f"cannot set ownership {uid}:{gid}: {error}", "apply_failed")


def atomic_write(path, text, mode, uid=None, gid=None):
    """Write a file atomically with its final mode/owner before it is visible."""
    target = absolute(path)
    ensure_no_symlink_ancestors(target)
    check_regular_or_absent(target, "target file")
    directory = target.parent
    tmp = directory / f".{target.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode)
        os.fchmod(descriptor, mode)
        _fchown_if_root(descriptor, uid, gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, target)
    except OSError as error:
        fail(f"cannot write {target}: {error}", "apply_failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    fsync_directory(directory)


def ensure_dir(path, mode, uid=None, gid=None):
    target = absolute(path)
    ensure_no_symlink_ancestors(target)
    try:
        info = target.lstat()
    except FileNotFoundError:
        info = None
    except OSError as error:
        fail(f"cannot inspect directory {target}: {error}", "path_unsafe")
    if info is not None and stat.S_ISLNK(info.st_mode):
        fail(f"directory is a symlink; refusing ({target})", "symlink_refused")
    if info is not None and not stat.S_ISDIR(info.st_mode):
        fail(f"path exists but is not a directory ({target})", "path_unsafe")
    if info is None:
        try:
            os.makedirs(target, mode=mode, exist_ok=True)
        except OSError as error:
            fail(f"cannot create directory {target}: {error}", "apply_failed")
    try:
        os.chmod(target, mode)
        if os.geteuid() == 0 and uid is not None and gid is not None:
            os.chown(target, uid, gid)
    except OSError as error:
        fail(f"cannot set directory permissions on {target}: {error}", "apply_failed")


def ensure_file_metadata(path, mode, uid=None, gid=None):
    info = check_regular_or_absent(path, "managed file")
    if info is None:
        return False
    try:
        if (info.st_mode & 0o777) != mode:
            os.chmod(path, mode)
        if os.geteuid() == 0 and uid is not None and gid is not None:
            if info.st_uid != uid or info.st_gid != gid:
                os.chown(path, uid, gid)
    except OSError as error:
        fail(f"cannot set permissions on {path}: {error}", "apply_failed")
    return True


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def private_json(path, label, owners, missing_code, invalid_code):
    info = check_regular_or_absent(path, label)
    if info is None:
        fail(f"{label} not found: {path}", missing_code)
    if info.st_mode & 0o077:
        fail(
            f"{label} must not be accessible by group/other "
            f"(mode {oct(info.st_mode & 0o777)}); chmod 600 {path}",
            "unsafe_permissions",
        )
    if info.st_uid not in owners:
        fail(
            f"{label} has an unexpected owner (uid {info.st_uid}); expected root "
            f"or the gateway service account ({path})",
            "unsafe_permissions",
        )
    raw = read_regular(path, label)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid UTF-8 JSON: {path}", invalid_code)


def normalized_ip(text, label, code="control_corrupt"):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        if "/" in str(text):
            fail(f"{label} must be a plain IP address, not a CIDR block ({text})", code)
        fail(f"{label} is not an IP address ({text})", code)


def slug_base(pbx_id):
    candidate = re.sub(r"[^a-z0-9]+", "-", pbx_id.lower()).strip("-")[:19].strip("-")
    if not candidate or not SLUG_RE.match(candidate):
        fail(f"cannot derive a safe tenant slug from PBX id {pbx_id}", "control_corrupt")
    return candidate


def derive_slug(pbx_id, taken):
    base = slug_base(pbx_id)
    if base not in taken:
        return base
    digest = hashlib.sha256(pbx_id.encode("utf-8")).hexdigest()[:8]
    candidate = f"{base[:10]}-{digest}"
    if candidate in taken:
        fail(f"tenant slug collision for PBX id {pbx_id}", "collision")
    return candidate


def slot_ports(slot):
    if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < MAX_SLOTS:
        fail(f"port slot {slot!r} is outside the managed range", "plan_corrupt")
    listener = LISTENER_BASE + slot
    relay_min = RELAY_BASE + slot * RELAY_SPAN
    relay_max = relay_min + RELAY_SPAN - 1
    if listener in RESERVED_LISTENER_PORTS or relay_max > 65535:
        fail(f"port slot {slot} collides with a reserved port", "plan_corrupt")
    return listener, relay_min, relay_max


def load_control(config):
    owners = {0}
    if config["service_uid"] is not None:
        owners.add(config["service_uid"])
    if os.geteuid() != 0 and config["dry_run"]:
        owners.add(os.geteuid())
    data = private_json(
        config["control_file"],
        "control store",
        owners,
        "control_missing",
        "control_corrupt",
    )
    if not isinstance(data, dict):
        fail("control store must contain a JSON object", "control_corrupt")
    version = data.get("schemaVersion", data.get("version"))
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        fail("control store is missing a valid schema version", "control_corrupt")
    if version > CONTROL_SCHEMA_VERSION:
        fail(
            f"control store schema {version} is newer than supported ({CONTROL_SCHEMA_VERSION})",
            "control_schema",
        )
    records = data.get("pbx", [])
    if not isinstance(records, list):
        fail('control store field "pbx" must be an array', "control_corrupt")

    parsed = []
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            fail("control store contains an invalid PBX record", "control_corrupt")
        pbx_id = record.get("id")
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id):
            fail(f"control store has an invalid PBX id ({pbx_id!r})", "control_corrupt")
        if pbx_id in seen:
            fail(f"control store contains duplicate PBX id {pbx_id}", "control_corrupt")
        seen.add(pbx_id)
        if not isinstance(record.get("name"), str) or not record["name"].strip():
            fail(f"PBX {pbx_id} has no name", "control_corrupt")
        if not isinstance(record.get("enabled"), bool):
            fail(f"PBX {pbx_id} field 'enabled' must be a boolean", "control_corrupt")
        media = record.get("mediaIps", [])
        if not isinstance(media, list):
            fail(f"PBX {pbx_id} field 'mediaIps' must be an array", "control_corrupt")
        peers = []
        for entry in media:
            if not isinstance(entry, str) or not entry.strip():
                fail(f"PBX {pbx_id} has an invalid mediaIps entry", "control_corrupt")
            text = entry.strip()
            normalized_ip(text, f"PBX {pbx_id} mediaIps entry")
            # Keep the operator's text verbatim: tenant-runtime compares the
            # manifest peers with the control store string-by-string.
            if text not in peers:
                peers.append(text)

        if record["enabled"] and not peers:
            fail(
                f"enabled PBX {pbx_id} has no mediaIps; an isolated relay needs "
                "explicit PBX peers",
                "control_corrupt",
            )
        parsed.append({"id": pbx_id, "name": record["name"].strip(), "enabled": record["enabled"], "peers": peers})
    return parsed


def load_plan(config):
    info = check_regular_or_absent(config["plan_file"], "allocation plan")
    if info is None:
        return {"allocations": {}, "relayIp": None}
    if info.st_mode & 0o077:
        fail(
            f"allocation plan must not be accessible by group/other; chmod 600 {config['plan_file']}",
            "unsafe_permissions",
        )
    raw = read_regular(config["plan_file"], "allocation plan")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("allocation plan is not valid UTF-8 JSON", "plan_corrupt")
    if not isinstance(data, dict):
        fail("allocation plan must contain a JSON object", "plan_corrupt")
    version = data.get("schemaVersion")
    if version != PLAN_SCHEMA_VERSION:
        fail(f"allocation plan schema {version!r} is not supported", "plan_corrupt")
    allocations = data.get("allocations", {})
    if not isinstance(allocations, dict):
        fail("allocation plan field 'allocations' must be an object", "plan_corrupt")

    slots = {}
    slugs = {}
    ports = {}
    clean = {}
    for pbx_id, entry in allocations.items():
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id):
            fail(f"allocation plan has an invalid PBX id ({pbx_id!r})", "plan_corrupt")
        if not isinstance(entry, dict):
            fail(f"allocation plan entry for {pbx_id} is invalid", "plan_corrupt")
        slug = entry.get("slug")
        if not isinstance(slug, str) or not SLUG_RE.match(slug):
            fail(f"allocation plan slug for {pbx_id} is invalid", "plan_corrupt")
        if slug in slugs:
            fail(f"allocation plan reuses slug {slug}", "plan_corrupt")
        slugs[slug] = pbx_id
        slot = entry.get("slot")
        listener, relay_min, relay_max = slot_ports(slot)
        if slot in slots:
            fail(f"allocation plan reuses slot {slot} ({slots[slot]} / {pbx_id})", "plan_corrupt")
        slots[slot] = pbx_id
        if (entry.get("listenerPort"), entry.get("relayMinPort"), entry.get("relayMaxPort")) != (
            listener,
            relay_min,
            relay_max,
        ):
            fail(f"allocation plan ports for {pbx_id} do not match their slot", "plan_corrupt")
        for port in (listener, relay_min):
            if port in ports:
                fail(f"allocation plan reuses port {port}", "plan_corrupt")
            ports[port] = pbx_id
        peers = entry.get("peerIps", [])
        if not isinstance(peers, list):
            fail(f"allocation plan peerIps for {pbx_id} must be an array", "plan_corrupt")
        clean_peers = []
        for peer in peers:
            if not isinstance(peer, str):
                fail(f"allocation plan peerIps for {pbx_id} is invalid", "plan_corrupt")
            normalized_ip(peer, f"allocation plan peerIps for {pbx_id}", "plan_corrupt")
            if peer not in clean_peers:
                clean_peers.append(peer)
        clean[pbx_id] = {
            "slug": slug,
            "slot": slot,
            "listenerPort": listener,
            "relayMinPort": relay_min,
            "relayMaxPort": relay_max,
            "peerIps": clean_peers,
        }
    environment = data.get("environment", {})
    previous_relay = None
    if isinstance(environment, dict):
        candidate = environment.get("relayIp")
        if isinstance(candidate, str) and candidate:
            previous_relay = normalized_ip(candidate, "allocation plan relayIp", "plan_corrupt")
    return {"allocations": clean, "relayIp": previous_relay}


def extend_allocations(allocations, control_records):
    """Assign a fresh slot/slug to every PBX id that has none yet.

    Slots are only ever added. Disabled and deleted PBXs keep their entry, so a
    port or slug is never handed to a different customer later.
    """
    used_slots = {entry["slot"] for entry in allocations.values()}
    taken_slugs = {entry["slug"] for entry in allocations.values()}
    pending = sorted(record["id"] for record in control_records if record["id"] not in allocations)
    for pbx_id in pending:
        slot = None
        for candidate in range(MAX_SLOTS):
            if candidate in used_slots:
                continue
            listener, _, _ = slot_ports(candidate)
            if listener in RESERVED_LISTENER_PORTS:
                continue
            slot = candidate
            break
        if slot is None:
            fail(
                f"no port slot left for {pbx_id} (capacity {MAX_SLOTS} PBXs)",
                "capacity_exceeded",
            )
        used_slots.add(slot)
        slug = derive_slug(pbx_id, taken_slugs)
        taken_slugs.add(slug)
        listener, relay_min, relay_max = slot_ports(slot)
        allocations[pbx_id] = {
            "slug": slug,
            "slot": slot,
            "listenerPort": listener,
            "relayMinPort": relay_min,
            "relayMaxPort": relay_max,
            "peerIps": [],
        }
    return allocations


def load_tokens(config):
    info = check_regular_or_absent(config["token_file"], "hook token file")
    if info is None:
        return {}
    if info.st_mode & 0o077:
        fail(
            f"hook token file must not be accessible by group/other; chmod 600 {config['token_file']}",
            "unsafe_permissions",
        )
    allowed = {0} if os.geteuid() == 0 else {0, os.geteuid()}
    if info.st_uid not in allowed:
        fail("hook token file must be root-owned", "unsafe_permissions")
    raw = read_regular(config["token_file"], "hook token file")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("hook token file is not valid UTF-8 JSON", "token_corrupt")
    if not isinstance(data, dict):
        fail("hook token file must contain a JSON object", "token_corrupt")
    tokens = {}
    for pbx_id, token in data.items():
        if not isinstance(pbx_id, str) or not PBX_ID_RE.match(pbx_id):
            fail(f"hook token file has an invalid PBX id ({pbx_id!r})", "token_corrupt")
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            fail(f"hook token for {pbx_id} is malformed", "token_corrupt")
        tokens[pbx_id] = token
    return tokens


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_env_file(path):
    target = absolute(path)
    info = check_regular_or_absent(target, "environment file")
    if info is None:
        fail(f"environment file not found: {target}", "env_invalid")
    if info.st_mode & 0o077:
        fail("environment file must not be accessible by group/other; chmod 600", "unsafe_permissions")
    for number, line in enumerate(read_regular(target, "environment file").decode("utf-8").splitlines(), 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if "=" not in text:
            fail(f"environment file line {number} is not KEY=VALUE", "env_invalid")
        key, value = text.split("=", 1)
        key = key.strip()
        if not key.startswith("GATEWAY_"):
            fail(f"environment file line {number} sets a non-GATEWAY variable", "env_invalid")
        os.environ.setdefault(key, value.strip().strip("'\""))


def require_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        fail(f"{name} is required", "env_invalid")
    return value


def resolve_user(name):
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return None, None
    return entry.pw_uid, entry.pw_gid


def load_config(args):
    if args.env_file:
        load_env_file(args.env_file)

    public_host = require_env("GATEWAY_PUBLIC_HOST")
    if len(public_host) > 253 or not HOST_RE.match(public_host) or ".." in public_host:
        fail("GATEWAY_PUBLIC_HOST is not a valid hostname", "env_invalid")
    listen_ip = normalized_ip(require_env("GATEWAY_LISTEN_IP"), "GATEWAY_LISTEN_IP")
    relay_ip = normalized_ip(require_env("GATEWAY_PRIVATE_IP"), "GATEWAY_PRIVATE_IP")
    for label, value in (("GATEWAY_LISTEN_IP", listen_ip), ("GATEWAY_PRIVATE_IP", relay_ip)):
        if ipaddress.ip_address(value).version != 4:
            fail(f"{label} must be an IPv4 address for coturn", "env_invalid")

    iface = args.iface or os.environ.get("GATEWAY_PRIVATE_IFACE") or "tailscale0"
    iface = iface.strip() or "tailscale0"
    if not IFACE_RE.match(iface):
        fail("GATEWAY_PRIVATE_IFACE is not a valid interface name", "env_invalid")
    service_user = args.service_user or os.environ.get("GATEWAY_SERVICE_USER") or "sokrat-push"
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", service_user):
        fail("GATEWAY_SERVICE_USER is not a valid account name", "env_invalid")

    state_dir = absolute(args.state_dir or os.environ.get("GATEWAY_STATE_DIR") or "/var/lib/sokrat-gateway")
    config = {
        "dry_run": bool(args.dry_run),
        "control_file": absolute(args.control or os.environ.get("GATEWAY_CONTROL_FILE") or state_dir / "control.json"),
        "state_dir": state_dir,
        "plan_file": absolute(args.trusted_state_dir) / "tenant-plan.json" if getattr(args,'trusted_state_dir',None) else state_dir / "tenant-plan.json",
        "manifest_file": state_dir / "tenant-runtime.json",
        "secret_dir": state_dir / "secrets",
        "token_file": absolute(args.trusted_state_dir) / "hook-tokens.json" if getattr(args,'trusted_state_dir',None) else state_dir / "hook-tokens.json",
        "turn_root": absolute(args.turn_root or os.environ.get("GATEWAY_TURN_ROOT") or "/etc/sokrat/turn"),
        "unit_dir": absolute(args.unit_dir or os.environ.get("GATEWAY_UNIT_DIR") or "/etc/systemd/system"),
        "unit_name": UNIT_TEMPLATE,
        "public_host": public_host,
        "listen_ip": listen_ip,
        "relay_ip": relay_ip,
        "iface": iface,
        "service_user": service_user,
        "firewall": not args.no_firewall,
    }
    config["service_uid"], config["service_gid"] = resolve_user(service_user)
    return config


def validate_state_dir(config):
    for field in ('plan_file','token_file'):
        directory = config[field].parent
        if directory != config['state_dir']:
            ensure_no_symlink_ancestors(directory)
            for parent in [directory,*directory.parents]:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    fail('Trusted state requires root-owned, non-writable ancestors','unsafe_permissions')
    target = config["state_dir"]
    ensure_no_symlink_ancestors(target)
    try:
        info = target.lstat()
    except FileNotFoundError:
        info = None
    if info is None:
        return
    if stat.S_ISLNK(info.st_mode):
        fail(f"state directory is a symlink; refusing ({target})", "symlink_refused")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"state path is not a directory ({target})", "path_unsafe")
    if info.st_mode & 0o002:
        fail(f"state directory is world-writable; refusing ({target})", "unsafe_permissions")


def require_traversable_ancestors(path, config, warnings):
    """The tenant TURN account must be able to walk to its own config file.

    /etc/sokrat is created 0700 by the control bootstrap on some hosts; coturn
    then cannot read its config even though the file itself is fine. Refuse
    (or warn in a dry run) with the exact remediation instead of starting a
    relay that will fail.
    """
    target = absolute(path)
    for parent in target.parents:
        if str(parent) == "/":
            break
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            fail(f"refusing to operate through symlinked directory {parent}", "symlink_refused")
        if info.st_mode & stat.S_IXOTH:
            continue
        message = (
            f"{parent} is not traversable by the tenant TURN account "
            f"(mode {oct(info.st_mode & 0o7777)}); run: chmod o+x {parent}"
        )
        if config["dry_run"]:
            warnings.append(message)
        else:
            fail(message, "environment_incomplete")


# ---------------------------------------------------------------------------
# Plan / manifest construction
# ---------------------------------------------------------------------------


def build_unit(config):
    conf_pattern = f"{config['turn_root']}/%i/turnserver.conf"
    return f"""# {CONF_MARKER} — do not edit by hand.
[Unit]
Description=Sokrat isolated tenant TURN relay %i
After=network-online.target tailscaled.service
Wants=network-online.target
ConditionPathExists={conf_pattern}

[Service]
Type=simple
User=sokrat-turn-%i
Group=sokrat-turn-%i
ExecStart=/usr/bin/turnserver -c {conf_pattern} --pidfile=
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
"""


def build_conf(tenant, secret, config):
    lines = [
        f"# {CONF_MARKER} ({tenant['pbxId']}) — do not edit by hand.",
        f"listening-port={tenant['listenerPort']}",
        f"listening-ip={config['listen_ip']}",
        f"relay-ip={tenant.get('relayIp', config['relay_ip'])}",
        f"min-port={tenant['relayMinPort']}",
        f"max-port={tenant['relayMaxPort']}",
        "fingerprint",
        "use-auth-secret",
        f"static-auth-secret={secret}",
        f"realm=sokrat-{tenant['slug']}",
        f"server-name=sokrat-{tenant['slug']}",
        "user-quota=12",
        "total-quota=200",
        "max-bps=256000",
        "bps-capacity=16000000",
        "stale-nonce=600",
        "no-tls",
        "no-dtls",
        "no-tcp-relay",
        "no-cli",
        "no-multicast-peers",
        "denied-peer-ip=0.0.0.0-255.255.255.255",
        "denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "log-file=stdout",
        "simple-log",
    ]
    lines.extend(f"allowed-peer-ip={peer}" for peer in tenant["peerIps"])
    return "\n".join(lines) + "\n"


def build_manifest(tenants, tokens):
    relays = {}
    hook_hashes = {}
    for tenant in tenants:
        if not tenant["enabled"]:
            continue
        if not tenant["peerIps"]:
            fail(f"enabled PBX {tenant['pbxId']} has no relay peers", "control_corrupt")
        relays[tenant["pbxId"]] = {
            "host": tenant["publicHost"],
            "port": tenant["listenerPort"],
            "secretFile": str(tenant["secretCopy"]),
            "peerIps": list(tenant["peerIps"]),
        }
        token = tokens.get(tenant["pbxId"])
        if token:
            hook_hashes[tenant["pbxId"]] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return {"relays": relays, "hookHashes": hook_hashes}


def prepare(args):
    config = load_config(args)
    validate_state_dir(config)

    control = load_control(config)
    plan = load_plan(config)
    allocations = extend_allocations(plan["allocations"], control)

    by_id = {record["id"]: record for record in control}
    tenants = []
    disabled = []
    for pbx_id in sorted(allocations):
        allocation = allocations[pbx_id]
        record = by_id.get(pbx_id)
        enabled = bool(record and record["enabled"])
        peers = record["peers"] if enabled else []
        tenant = {
            "pbxId": pbx_id,
            "slug": allocation["slug"],
            "slot": allocation["slot"],
            "listenerPort": allocation["listenerPort"],
            "relayMinPort": allocation["relayMinPort"],
            "relayMaxPort": allocation["relayMaxPort"],
            "publicHost": config["public_host"],
            "secretCopy": config["secret_dir"] / f"{allocation['slug']}.secret",
            "unit": UNIT_TEMPLATE.replace("@.service", f"@{allocation['slug']}.service"),
            "user": f"sokrat-turn-{allocation['slug']}",
            "previousPeers": allocation["peerIps"],
            "peerIps": sorted(peers),
            "enabled": enabled,
            "removed": record is None,
            "secret": None,
            "confChanged": False,
            "actions": [],
        }
        # A media link is accepted only from root-installed material. The web
        # store cannot select an arbitrary relay bind address or interface.
        media_dir = Path('/etc/sokrat/media') / pbx_id
        media_plan = media_dir / 'plan.json'
        if media_plan.exists():
            ensure_no_symlink_ancestors(media_plan)
            info = media_plan.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                fail('Untrusted media link plan', 'unsafe_permissions')
            try:
                # Import beside this reviewed script, never from app/PYTHONPATH.
                import importlib.util
                spec = importlib.util.spec_from_file_location('sokrat_media', Path(__file__).with_name('tunnel_media.py'))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                link = module.validate_plan(json.loads(read_regular(media_plan, 'media link plan')))
            except (ValueError, TypeError, KeyError):
                fail('Invalid media link plan', 'control_corrupt')
            if link['pbxId'] != pbx_id or link['slot'] != tenant['slot']:
                fail('Media and TURN allocation mismatch', 'plan_corrupt')
            # Keep the interface for removing old rules after disable/retire,
            # when the dashboard no longer supplies any current peer list.
            if allocation['peerIps'] == [link['pbxIp']]:
                tenant['previousMediaIface'] = link['interface']
                tenant['previousRelayIp'] = link['gatewayIp']
            # Staging a media link must not switch a working tenant before its
            # media identity is explicitly changed/reviewed in the dashboard.
            if peers == [link['pbxIp']]:
                tenant['relayIp'] = link['gatewayIp']
                tenant['mediaIface'] = link['interface']
        tenant["secretDir"] = config["turn_root"] / allocation["slug"]
        tenant["secretFile"] = tenant["secretDir"] / "secret"
        tenant["confFile"] = tenant["secretDir"] / "turnserver.conf"
        if enabled:
            tenants.append(tenant)
        else:
            disabled.append(tenant)

    # Validate every target before any write, and read reusable secrets.
    for tenant in tenants:
        info = check_regular_or_absent(tenant["secretFile"], "TURN secret")
        if info is not None:
            text = read_regular(tenant["secretFile"], "TURN secret").decode("utf-8", "replace").strip()
            if not HEX_SECRET_RE.match(text):
                fail(
                    f"existing TURN secret for {tenant['pbxId']} is malformed; "
                    "refusing to overwrite it",
                    "secret_invalid",
                )
            if info.st_mode & 0o077:
                fail(
                    f"TURN secret for {tenant['pbxId']} is not private "
                    f"(mode {oct(info.st_mode & 0o777)})",
                    "unsafe_permissions",
                )
            tenant["secret"] = text
            tenant["actions"].append("reuse TURN secret")
        else:
            tenant["actions"].append("create TURN secret")
        check_regular_or_absent(tenant["confFile"], "coturn config")
        check_regular_or_absent(tenant["secretCopy"], "service secret copy")
        tenant["actions"].extend(
            [
                f"ensure user {tenant['user']}",
                f"write coturn config (listener {tenant['listenerPort']}, "
                f"relay {tenant['relayMinPort']}-{tenant['relayMaxPort']})",
                f"publish secret copy {tenant['secretCopy']}",
                f"permit ufw {tenant['listenerPort']}/tcp+udp and "
                f"{len(tenant['peerIps'])} PBX peer(s)",
                f"enable --now {tenant['unit']}",
            ]
        )
    for tenant in disabled:
        check_regular_or_absent(tenant["secretCopy"], "service secret copy")
        tenant["actions"] = [
            f"stop/disable {tenant['unit']}",
            f"remove ufw rules for {tenant['listenerPort']}",
            f"remove service secret copy {tenant['secretCopy']}",
            "omit from runtime manifest",
        ]

    check_regular_or_absent(config["manifest_file"], "runtime manifest")

    tokens = load_tokens(config)
    missing_tokens = [t["pbxId"] for t in tenants if t["pbxId"] not in tokens]
    manifest = build_manifest(tenants, tokens)

    unit_path = config["unit_dir"] / UNIT_TEMPLATE
    existing_unit = check_regular_or_absent(unit_path, "systemd unit")
    if existing_unit is not None:
        current = read_regular(unit_path, "systemd unit").decode("utf-8", "replace")
        desired = build_unit(config)
        if UNIT_MARKER not in current and current != desired:
            fail(
                f"{unit_path} exists and was not written by this command; "
                "refusing to overwrite an unmanaged unit",
                "unmanaged_file",
            )

    warnings = []
    if config["service_uid"] is None:
        warnings.append(f"service account {config['service_user']} does not exist yet")
    require_traversable_ancestors(config["turn_root"], config, warnings)
    if not config["dry_run"]:
        if os.geteuid() != 0:
            fail("this command must run as root to provision relays", "not_root")
        if tenants and config["service_uid"] is None:
            fail(
                f"service account {config['service_user']} is required to publish "
                "relay secrets and the runtime manifest",
                "environment_incomplete",
            )
        if tenants and not Path("/usr/bin/turnserver").exists():
            fail("/usr/bin/turnserver is missing; install coturn first", "environment_incomplete")
    elif tenants and not Path("/usr/bin/turnserver").exists():
        warnings.append("coturn (/usr/bin/turnserver) is not installed on this host")
    if config["firewall"] and shutil_which("ufw") is None:
        warnings.append("ufw is not installed; relay listener/peer rules were not changed")
        config["firewall"] = False

    return {
        "config": config,
        "control": control,
        "allocations": allocations,
        "tenants": tenants,
        "disabled": disabled,
        "tokens": tokens,
        "missingTokens": missing_tokens,
        "manifest": manifest,
        "previousRelayIp": plan.get("relayIp"),
        "warnings": warnings,
    }


def shutil_which(name):
    for directory in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def run(argv, warnings, label, check=True, capture=True, optional=False):
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=capture,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        if check:
            fail(f"{label} failed: {error}", "apply_failed")
        if not optional:
            warnings.append(f"{label} failed: {error}")
        return None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        message = detail[-1] if detail else f"exit {result.returncode}"
        if check:
            fail(f"{label} failed: {message}", "apply_failed")
        if not optional:
            warnings.append(f"{label}: {message}")
    return result


def systemctl(args, warnings, check=False, optional=False):
    return run(
        ["systemctl", *args],
        warnings,
        f"systemctl {' '.join(args)}",
        check=check,
        optional=optional,
    )


def ufw(args, warnings, check=False, optional=False):
    if not args:
        return None
    return run(
        ["ufw", *args],
        warnings,
        f"ufw {' '.join(args)}",
        check=check,
        optional=optional,
    )


def ensure_service_user(user, warnings):
    try:
        pwd.getpwnam(user)
        return
    except KeyError:
        pass
    run(
        ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", user],
        warnings,
        f"create system user {user}",
        check=True,
    )


def listener_firewall(tenant, add, warnings):
    port = tenant["listenerPort"]
    for proto in ("tcp", "udp"):
        spec = ["allow", f"{port}/{proto}"] if add else ["delete", "allow", f"{port}/{proto}"]
        ufw(spec, warnings, check=add, optional=not add)


def peer_firewall(tenant, peer, add, warnings, config, relay_ip=None, iface=None):
    spec = [
        "in",
        "on",
        iface or tenant.get("mediaIface", config["iface"]),
        "from",
        peer,
        "to",
        relay_ip or tenant.get("relayIp", config["relay_ip"]),
        "port",
        f"{tenant['relayMinPort']}:{tenant['relayMaxPort']}",
        "proto",
        "udp",
    ]
    ufw(["allow", *spec] if add else ["delete", "allow", *spec], warnings, check=add, optional=not add)


def provision_tenant(tenant, state, warnings):
    config = state["config"]
    user = tenant["user"]
    ensure_service_user(user, warnings)
    account = pwd.getpwnam(user)

    ensure_dir(config["turn_root"], 0o711, 0, 0)
    ensure_dir(tenant["secretDir"], 0o750, 0, account.pw_gid)

    secret = tenant["secret"]
    if secret is None:
        secret = secrets.token_hex(32)
        atomic_write(tenant["secretFile"], secret + "\n", 0o600, 0, 0)
        tenant["secret"] = secret
    else:
        ensure_file_metadata(tenant["secretFile"], 0o600, 0, 0)

    conf = build_conf(tenant, secret, config)
    conf_file = tenant["confFile"]
    info = check_regular_or_absent(conf_file, "coturn config")
    if info is None or read_regular(conf_file, "coturn config").decode("utf-8", "replace") != conf:
        atomic_write(conf_file, conf, 0o640, 0, account.pw_gid)
        tenant["confChanged"] = True
    else:
        ensure_file_metadata(conf_file, 0o640, 0, account.pw_gid)

    if config["service_uid"] is None:
        warnings.append(f"cannot publish secret copy: service account {config['service_user']} missing")
    else:
        ensure_dir(config["secret_dir"], 0o700, config["service_uid"], config["service_gid"])
        payload = secret + "\n"
        copy = tenant["secretCopy"]
        info = check_regular_or_absent(copy, "service secret copy")
        current = read_regular(copy, "service secret copy").decode("utf-8", "replace") if info else None
        if current != payload:
            atomic_write(
                copy,
                payload,
                0o600,
                config["service_uid"],
                config["service_gid"],
            )
        else:
            ensure_file_metadata(copy, 0o600, config["service_uid"], config["service_gid"])

    if config["firewall"]:
        listener_firewall(tenant, True, warnings)
        previous = set(tenant["previousPeers"])
        current_peers = set(tenant["peerIps"])
        for peer in sorted(current_peers):
            peer_firewall(tenant, peer, True, warnings, config)
        old_relay = tenant.get('previousRelayIp') or state.get("previousRelayIp") or config['relay_ip']
        old_iface = tenant.get('previousMediaIface', config['iface'])
        if (old_relay != tenant.get('relayIp', config['relay_ip'])
                or old_iface != tenant.get('mediaIface', config['iface'])):
            # The relay address changed: every previous peer rule targets the
            # old address and must be removed there, not on the new one.
            for peer in sorted(previous):
                peer_firewall(tenant, peer, False, warnings, config, relay_ip=old_relay, iface=old_iface)
        else:
            for peer in sorted(previous - current_peers):
                peer_firewall(tenant, peer, False, warnings, config, relay_ip=old_relay, iface=old_iface)
        # The plan records what ufw actually allows, so it is only updated when
        # firewall management is enabled for this run.
        state["allocations"][tenant["pbxId"]]["peerIps"] = list(tenant["peerIps"])


def revoke_tenant(tenant, state, warnings):
    config = state["config"]
    systemctl(["disable", "--now", tenant["unit"]], warnings, optional=True)
    if config["firewall"]:
        listener_firewall(tenant, False, warnings)
        old_relay = tenant.get('previousRelayIp') or state.get("previousRelayIp") or config["relay_ip"]
        for peer in sorted(set(tenant["previousPeers"])):
            peer_firewall(tenant, peer, False, warnings, config, relay_ip=old_relay,
                          iface=tenant.get('previousMediaIface', config['iface']))
    copy = tenant["secretCopy"]
    info = check_regular_or_absent(copy, "service secret copy")
    if info is not None:
        try:
            os.unlink(copy)
            fsync_directory(copy.parent)
        except OSError as error:
            warnings.append(f"could not remove {copy}: {error}")
        state["allocations"][tenant["pbxId"]]["peerIps"] = []


def write_unit(config):
    unit_path = config["unit_dir"] / UNIT_TEMPLATE
    desired = build_unit(config)
    info = check_regular_or_absent(unit_path, "systemd unit")
    if info is not None:
        current = read_regular(unit_path, "systemd unit").decode("utf-8", "replace")
        if current == desired:
            return
        if UNIT_MARKER not in current:
            fail(f"{unit_path} is unmanaged; refusing to overwrite it", "unmanaged_file")
    ensure_dir(config["unit_dir"], 0o755, 0, 0)
    atomic_write(unit_path, desired, 0o644, 0, 0)


def apply_state(state, args):
    config = state["config"]
    warnings = state["warnings"]

    for tenant in state["disabled"]:
        revoke_tenant(tenant, state, warnings)

    write_unit(config)
    systemctl(["daemon-reload"], warnings, check=True)

    for tenant in state["tenants"]:
        provision_tenant(tenant, state, warnings)

    tokens = dict(state["tokens"])
    for tenant in state["tenants"]:
        if tenant["pbxId"] not in tokens:
            tokens[tenant["pbxId"]] = secrets.token_urlsafe(32)
    state["tokens"] = tokens
    state["manifest"] = build_manifest(state["tenants"], tokens)

    plan_doc = {
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "generatedAt": iso_timestamp(),
        "environment": {
            "publicHost": config["public_host"],
            "listenIp": config["listen_ip"],
            "relayIp": config["relay_ip"],
        },
        "allocations": {key: state["allocations"][key] for key in sorted(state["allocations"])},
    }
    atomic_write(config["plan_file"], json.dumps(plan_doc, indent=2, sort_keys=True) + "\n", 0o600, 0, 0)

    atomic_write(
        config["token_file"],
        json.dumps(tokens, indent=2, sort_keys=True) + "\n",
        0o600,
        0,
        0,
    )

    atomic_write(
        config["manifest_file"],
        json.dumps(state["manifest"], indent=2, sort_keys=True) + "\n",
        0o600,
        config["service_uid"],
        config["service_gid"],
    )

    for tenant in state["tenants"]:
        systemctl(["enable", "--now", tenant["unit"]], warnings, check=True)
        if tenant["confChanged"]:
            systemctl(["restart", tenant["unit"]], warnings, check=True)

    state["missingTokens"] = []
    state["applied"] = True
    return 1 if warnings else 0


def iso_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def emit(state, mode):
    config = state["config"]
    if state.get("json_output"):
        payload = {
            "ok": True if mode == "dry-run" else not state["warnings"],
            "mode": mode,
            "publicHost": config["public_host"],
            "listenIp": config["listen_ip"],
            "relayIp": config["relay_ip"],
            "state": {
                "planFile": str(config["plan_file"]),
                "manifestFile": str(config["manifest_file"]),
                "secretDir": str(config["secret_dir"]),
                "hookTokenFile": str(config["token_file"]),
                "unit": str(config["unit_dir"] / UNIT_TEMPLATE),
            },
            "tenants": [
                {
                    "pbxId": tenant["pbxId"],
                    "slug": tenant["slug"],
                    "enabled": tenant["enabled"],
                    "listenerPort": tenant["listenerPort"],
                    "relayRange": [tenant["relayMinPort"], tenant["relayMaxPort"]],
                    "peerIps": tenant["peerIps"],
                    "unit": tenant["unit"],
                    "actions": tenant["actions"],
                }
                for tenant in state["tenants"]
            ],
            "disabled": [
                {
                    "pbxId": tenant["pbxId"],
                    "slug": tenant["slug"],
                    "removed": tenant["removed"],
                    "listenerPort": tenant["listenerPort"],
                    "actions": tenant["actions"],
                }
                for tenant in state["disabled"]
            ],
            "manifest": {
                "relays": sorted(state["manifest"]["relays"]),
                "hookHashes": sorted(state["manifest"]["hookHashes"]),
                "pendingHookTokens": sorted(state["missingTokens"]),
            },
            "warnings": state["warnings"],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    print(f"mode: {mode}")
    print(f"public host: {config['public_host']}")
    print(f"listener/relay: {config['listen_ip']} / {config['relay_ip']}")
    print(f"plan: {config['plan_file']}")
    print(f"manifest: {config['manifest_file']}")
    print(f"service secret dir: {config['secret_dir']}")
    print(f"root-only hook tokens: {config['token_file']}")
    print("")
    if not state["tenants"] and not state["disabled"]:
        print("no PBX records in the control store; nothing to provision")
    for tenant in state["tenants"]:
        print(
            f"[enabled] {tenant['pbxId']}  slug={tenant['slug']}  "
            f"listener={tenant['listenerPort']}  relay={tenant['relayMinPort']}-{tenant['relayMaxPort']}  "
            f"peers={','.join(tenant['peerIps'])}"
        )
        for action in tenant["actions"]:
            print(f"  - {action}")
    for tenant in state["disabled"]:
        label = "removed" if tenant["removed"] else "disabled"
        print(f"[{label}] {tenant['pbxId']}  slug={tenant['slug']}  listener={tenant['listenerPort']}")
        for action in tenant["actions"]:
            print(f"  - {action}")
    manifest = state["manifest"]
    print("")
    print(
        f"runtime manifest: {len(manifest['relays'])} relay(s), "
        f"{len(manifest['hookHashes'])} hook hash(es)"
    )
    if state["missingTokens"]:
        print(
            "hook tokens to generate (not printed): " + ", ".join(state["missingTokens"])
        )
    for warning in state["warnings"]:
        print(f"warning: {warning}")
    if mode == "dry-run":
        print("dry run: no files, services or firewall rules were changed")
    elif state.get("applied"):
        print(
            "Restart the service that hosts the tenant runtime to load the new manifest "
            "(sokrat-gateway-control or sokrat-push-gateway)."
        )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="sync-tenant-runtime.py",
        description=(
            "Provision per-PBX isolated TURN relays and the private tenant runtime "
            "manifest from the gateway control store."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ./scripts/sync-tenant-runtime.py --dry-run\n"
            "  sudo GATEWAY_PUBLIC_HOST=gw.example.com GATEWAY_LISTEN_IP=10.0.0.5 \\\n"
            "       GATEWAY_PRIVATE_IP=10.8.0.2 ./scripts/sync-tenant-runtime.py\n"
        ),
    )
    parser.add_argument("--control", help="control store JSON (default /var/lib/sokrat-gateway/control.json)")
    parser.add_argument("--state-dir", help="state directory (default /var/lib/sokrat-gateway)")
    parser.add_argument("--trusted-state-dir", help="root-owned directory for allocation plan and hook tokens")
    parser.add_argument("--turn-root", help="coturn config root (default /etc/sokrat/turn)")
    parser.add_argument("--unit-dir", help="systemd unit directory (default /etc/systemd/system)")
    parser.add_argument("--iface", dest="iface", help="private interface for peer ACLs (default tailscale0)")
    parser.add_argument("--service-user", help="account that runs the gateway (default sokrat-push)")
    parser.add_argument("--env-file", help="read GATEWAY_* variables from a private KEY=VALUE file")
    parser.add_argument("--dry-run", action="store_true", help="validate and print the plan only")
    parser.add_argument("--json", action="store_true", dest="json_output", help="machine-readable output")
    parser.add_argument("--no-firewall", action="store_true", help="do not touch ufw rules")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    started = False
    try:
        state = prepare(args)
        state["json_output"] = args.json_output
        if args.dry_run:
            emit(state, "dry-run")
            return 0
        started = True
        code = apply_state(state, args)
        emit(state, "applied")
        return code
    except SyncError as error:
        print(f"sync-tenant-runtime: refused [{error.code}]: {error}", file=sys.stderr)
        if started:
            print(
                "Provisioning stopped. Completed steps are idempotent; fix the "
                "reported problem and re-run.",
                file=sys.stderr,
            )
        else:
            print("No changes were made.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
