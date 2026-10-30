#!/usr/bin/env python3
"""Root-owned reverse TLS enrollment and FRP authorization service.

The HTTPS bootstrap certificate is carried in the operator's pairing code.
Installation secrets are generated on the PBX; only hashes persist here. A
shared pairing code can create a new installation, never take over an old one.
FRP's plugin enforces installation credentials AND exact per-tenant proxy ports.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import threading
import urllib.parse

from tunnel_media import allocation, validate_plan
from tunnel_media_material import new_material, for_role

ROOT = Path('/etc/sokrat/tunnel-enrollment')
CONFIG = ROOT / 'config.json'
REGISTRY = ROOT / 'installations.json'
PAIRING_FILE = Path('/etc/sokrat/gateway-tunnel-enrollment.token')
BRIDGE_FILE = Path('/etc/sokrat/gateway-tunnel-bridge.token')
PLAN = Path('/var/lib/sokrat-gateway/tenant-plan.json')
HOOKS = Path('/var/lib/sokrat-gateway/hook-tokens.json')
CONTROL = Path('/var/lib/sokrat-gateway/control.json')
ID_RE = re.compile(r'^[a-f0-9]{32}$')
SECRET_RE = re.compile(r'^[A-Za-z0-9_-]{43,128}$')
LOCK = threading.Lock()


def load_installer():
    spec = importlib.util.spec_from_file_location('media_installer', Path(__file__).with_name('install-media-link.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path, default=None):
    # File ownership is insufficient when a service-owned ancestor can replace
    # the directory entry. All privileged state lives below root-owned parents.
    for directory in [path.parent,*path.parent.parents]:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted root state directory')
    try:
        info = path.lstat()
    except FileNotFoundError:
        return default
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Untrusted root state')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
                or opened.st_mode & 0o077 or opened.st_size > 2*1024*1024):
            raise ValueError('Untrusted root state')
        raw = stream.read(2*1024*1024 + 1)
    if len(raw) > 2*1024*1024:
        raise ValueError('Oversized root state')
    return json.loads(raw)


def save_json(path, data):
    load_installer().private_directory(path.parent)
    load_installer().write(path, json.dumps(data, indent=2, sort_keys=True) + '\n', 0o600)


def trusted_state(config):
    directory = Path(config['trustedStateDir'])
    load_installer().private_directory(directory)
    return directory / 'tenant-plan.json', directory / 'hook-tokens.json'


def pin(entry):
    path = Path('/etc/sokrat/gateway-provisioning.json')
    config = read_json(path)
    ws = 'ws://127.0.0.1:%d/ws' % entry['ports']['ws']
    api = 'http://127.0.0.1:%d/' % entry['ports']['api']
    identity = {'approval':'approved','apiURL':api,'mediaIps':[entry['plan']['pbxIp']],'wsURL':ws}
    identity['fingerprint'] = hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    identity['hookAdapter'] = str(Path(__file__).with_name('check-tunnel-readiness.py'))
    config.setdefault('pbx',{})[entry['pbxId']] = identity
    save_json(path,config)


def hash_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def valid_installation(body):
    if (not isinstance(body, dict) or not isinstance(body.get('installationId'), str)
            or not ID_RE.fullmatch(body['installationId'])):
        raise ValueError('Invalid installation identity')
    if (not isinstance(body.get('installationSecret'), str)
            or not SECRET_RE.fullmatch(body['installationSecret'])):
        raise ValueError('Invalid installation credential')
    name = body.get('name')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,63}', name):
        raise ValueError('Invalid PBX name')


def proxy_ports(slot):
    if type(slot) is not int or not 0 <= slot < 155:
        raise ValueError('Invalid tenant slot')
    return {'ws': 23000 + slot * 2, 'api': 23001 + slot * 2, 'media': 22000 + slot}


def authorize_plugin(operation, content, installations):
    if operation not in ('Login', 'NewProxy', 'Ping', 'NewWorkConn') or not isinstance(content, dict):
        return False
    identity = content if operation == 'Login' else content.get('user', {})
    if not isinstance(identity, dict):
        return False
    user = identity.get('user')
    metas = identity.get('metas', {})
    if not isinstance(metas, dict):
        return False
    record = next((row for row in installations.values() if row['pbxId'] == user), None)
    supplied = metas.get('installationSecret', '')
    if (not record or record.get('migrationExpected') or not isinstance(supplied, str)
            or not hmac.compare_digest(hash_secret(supplied), record['secretHash'])):
        return False
    if operation == 'NewProxy':
        if content.get('proxy_type') != 'tcp' or content.get('group') or content.get('group_key'):
            return False
        allowed = {user + '.' + kind: port for kind, port in record['ports'].items()}
        return content.get('proxy_name') in allowed and type(content.get('remote_port')) is int and allowed[content['proxy_name']] == content['remote_port']
    return True


def plugin_operation(body, path):
    operation = body.get('op')
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query, keep_blank_values=True)
    if 'op' in query and query['op'] != [operation]:
        raise ValueError('Conflicting plugin operation')
    return operation


def firewall_request(config, body, supplied):
    expected = BRIDGE_FILE.read_text().strip()
    if not expected or not hmac.compare_digest(expected,supplied):
        raise ValueError('Local firewall credential required')
    pbx_id = body.get('pbxId')
    if not isinstance(pbx_id,str) or type(body.get('enabled')) is not bool:
        raise ValueError('Explicit tenant firewall request required')
    plan_path,_ = trusted_state(config)
    plan = read_json(plan_path)
    row = plan['allocations'][pbx_id]
    slot = row['slot']
    proxy_ports(slot)  # bounded integer; never trust an arbitrary host port
    port = 3500 + slot
    if body.get('listenerPort') != port or row.get('listenerPort') != port:
        raise ValueError('Tenant listener allocation mismatch')
    if body['enabled']:
        worker = read_json(Path('/etc/sokrat/gateway-provisioning.json'))
        if pbx_id not in worker.get('pbx',{}):
            raise ValueError('Root-reviewed tenant required')
        # Control state can revoke, never select a privileged port or command.
        with CONTROL.open() as stream:
            records = json.loads(stream.read(2*1024*1024))['pbx']
        if not any(record['id']==pbx_id and record.get('enabled') is True
                   and record.get('management',{}).get('approvalStatus')=='approved'
                   for record in records):
            raise ValueError('Tenant disabled or unapproved')
    spec = importlib.util.spec_from_file_location('host_firewall',Path(__file__).with_name('provisioning-firewall-local.py'))
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    adapter.configure(port,body['enabled'])
    return {'success':True}


def bridge(config, entry, name):
    body = json.dumps({'pbxId': entry['pbxId'], 'installationId': entry['installationId'],
                       'name': name, 'ports': entry['ports'], 'mediaIp': entry['plan']['pbxIp'],
                       'existingRequired':entry.get('controlRegistered',False),
                       **({'migrationExpected':entry['migrationExpected']} if entry.get('migrationExpected') else {})})
    conn = http.client.HTTPConnection('127.0.0.1', config['controlPort'], timeout=15)
    try:
        conn.request('POST', '/control/api/tunnel/register-v2', body,
                     {'Content-Type': 'application/json', 'X-Sokrat-Tunnel-Bridge': BRIDGE_FILE.read_text().strip()})
        response = conn.getresponse()
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError('Control enrollment refused')
        result = json.loads(raw)
        if not result.get('success'):
            raise ValueError('Control enrollment refused')
        return result
    finally:
        conn.close()


def reserve(config, installations, body):
    identifier = body['installationId']
    if identifier in installations:
        entry = installations[identifier]
        if not hmac.compare_digest(entry['secretHash'], hash_secret(body['installationSecret'])):
            raise ValueError('Installation credential refused')
        validate_plan(entry['plan'])
        if entry['ports'] != proxy_ports(entry['plan']['slot']):
            raise ValueError('Invalid registered ports')
        return entry
    if not hmac.compare_digest(str(body.get('pairingSecret', '')), config['pairingSecret']):
        raise ValueError('Pairing credential refused')
    # Merge reserved slots from retired tenants too. Never recycle allocations.
    plan_path,_ = trusted_state(config)
    plan = read_json(plan_path, {'schemaVersion': 1, 'allocations': {}})
    # Use the exact allocator validation used by reconciliation. Root ownership
    # does not make a stale/corrupt allocation safe to turn into network services.
    spec = importlib.util.spec_from_file_location('tenant_allocator', Path(__file__).with_name('sync-tenant-runtime.py'))
    allocator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(allocator)
    allocator.load_plan({'plan_file':plan_path})
    used = {row['slot'] for row in plan['allocations'].values()}
    used.update(row['plan']['slot'] for row in installations.values())
    slot = next((n for n in range(155) if n not in used), None)
    if slot is None:
        raise ValueError('Tenant capacity reached')
    pbx_id = 'pbx_' + secrets.token_hex(8)
    media = allocation(pbx_id, slot, config['mediaPool'])
    entry = {'pbxId': pbx_id, 'installationId': identifier,
             'secretHash': hash_secret(body['installationSecret']),
             'plan': media, 'ports': proxy_ports(slot)}
    material = new_material(media)
    material['readinessKey'] = secrets.token_urlsafe(32)
    directory = ROOT / pbx_id
    installer = load_installer()
    installer.private_directory(directory)
    save_json(directory / 'material.json', material)
    # Reserve coturn's matching slot before creating a control record. A failure
    # leaves a retired allocation, not a port handed to another installation.
    slug = allocator.derive_slug(pbx_id, {row['slug'] for row in plan['allocations'].values()})
    plan['allocations'][pbx_id] = {'slug': slug, 'slot': slot, 'listenerPort':3500 + slot,
        'relayMinPort':50000 + slot * 100, 'relayMaxPort':50099 + slot * 100, 'peerIps':[]}
    save_json(plan_path, plan)
    installations[identifier] = entry
    save_json(REGISTRY, installations)
    # Retry can repair a failed install using the same persisted identity/keys.
    # Never start an unrecorded service or hand its slot to another tenant.
    return entry


def register(config, body):
    valid_installation(body)
    # Validate bootstrap response prerequisites BEFORE adopting control routes.
    # Legacy gateways may have a shorter pre-shared token; never strand a PBX
    # on new routes only for its client to reject the returned credentials.
    frp_token = Path(config['frpTokenFile']).read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,200}',frp_token):
        raise ValueError('Secure FRP credential required before enrollment')
    with LOCK:
        worker_config = read_json(Path('/etc/sokrat/gateway-provisioning.json'))
        lock_path = Path(worker_config.get('lockDir','/run/sokrat-tenant-provisioning'))
        load_installer().private_directory(lock_path)
        fd = os.open(str(lock_path/'lock'), os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK, 0o600)
        with os.fdopen(fd,'r+b') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError('Untrusted provisioning lock')
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            installations = read_json(REGISTRY, {})
            entry = reserve(config, installations, body)
            _,hooks_path = trusted_state(config)
            hooks = read_json(hooks_path, {})
            if entry['pbxId'] not in hooks:
                hooks[entry['pbxId']] = secrets.token_urlsafe(32)
                save_json(hooks_path, hooks)
            result = bridge(config, entry, body['name'])
            if (result.get('enabled') is not True
                    or result.get('approvalStatus') != 'approved'):
                raise ValueError('PBX is disabled or pending review')
            if entry.pop('migrationExpected',None):
                save_json(REGISTRY,installations)
            if not entry.get('controlRegistered'):
                entry['controlRegistered'] = True
                save_json(REGISTRY,installations)
            pin(entry)
            material = read_json(ROOT / entry['pbxId'] / 'material.json')
            # Approval is checked before any service start. A disabled tenant's
            # saved credential must not restart its media service on retry.
            load_installer().install({'plan':entry['plan'], 'material':for_role(material,'gateway')},'gateway',True)
        return {'success':True, 'pbxId':entry['pbxId'], 'installationId':entry['installationId'],
                'plan':entry['plan'], 'material':for_role(material, 'pbx'), 'ports':entry['ports'],
                'tunnelPort':config['tunnelPort'], 'serverHost':config['publicHost'],
                'serverCa':(ROOT / 'server.crt').read_text(), 'serverName':config['publicHost'],
                'frpToken':frp_token,
                'hookToken':hooks[entry['pbxId']], 'readinessKey':material['readinessKey'],
                'gatewayUrl':config['gatewayUrl']}


def stage_migration(body):
    """Root-only explicit adoption. Does not change control routes or call paths.

    Operator supplies the reviewed public PBX digest and the installation's
    generated credentials via private stdin, never the public registration API.
    """
    valid_installation(body)
    pbx_id = body.get('pbxId','')
    if not re.fullmatch(r'pbx_[a-f0-9]{16}',pbx_id) or not re.fullmatch(r'[a-f0-9]{64}',str(body.get('expectedDigest',''))):
        raise ValueError('Explicit PBX review required')
    config = read_json(CONFIG)
    worker = read_json(Path('/etc/sokrat/gateway-provisioning.json'))
    if worker.get('runtime',{}).get('trustedStateDir') != config['trustedStateDir']:
        raise ValueError('Enrollment and reconciler must share trusted allocation state')
    directory = Path(worker.get('lockDir','/run/sokrat-tenant-provisioning'))
    installer = load_installer()
    installer.private_directory(directory)
    fd = os.open(str(directory/'lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+b') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        rows = read_json(REGISTRY,{})
        if body['installationId'] in rows or any(row['pbxId']==pbx_id for row in rows.values()):
            raise ValueError('Installation or PBX is already assigned')
        plan_path,_ = trusted_state(config)
        plan = read_json(plan_path)
        slot = plan['allocations'][pbx_id]['slot']
        media = allocation(pbx_id,slot,config['mediaPool'])
        material = new_material(media)
        material['readinessKey'] = secrets.token_urlsafe(32)
        target = ROOT/pbx_id
        installer.private_directory(target)
        save_json(target/'material.json',material)
        rows[body['installationId']] = {'pbxId':pbx_id,'installationId':body['installationId'],
            'secretHash':hash_secret(body['installationSecret']),'ports':proxy_ports(slot),
            'plan':media,'migrationExpected':body['expectedDigest']}
        save_json(REGISTRY,rows)
    print('Staged explicit installation adoption; control routing is unchanged until enrollment')


def initialize(args):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import pwd
    if CONFIG.exists():
        raise ValueError('Already initialized; credentials preserved')
    # Validate the service account before writing any bootstrap credentials.
    group = pwd.getpwnam(args.service_user).pw_gid
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', args.host):
        raise ValueError('Public host required')
    allocation('pbx_0123456789abcdef', 154, args.pool)
    gateway = urllib.parse.urlsplit(args.gateway_url)
    if (gateway.scheme != 'https' or gateway.hostname != args.host or gateway.port != args.port
            or gateway.username or gateway.password or gateway.path not in ('','/')
            or gateway.query or gateway.fragment):
        raise ValueError('Gateway URL must match the public host')
    # Refuse pools overlapping any existing non-default local route.
    routes = json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all']))
    pool = ipaddress.ip_network(args.pool)
    for route in routes:
        destination = route.get('dst', 'default')
        if destination != 'default' and pool.overlaps(ipaddress.ip_network(destination, strict=False)):
            # A deliberately installed validation link is permitted only when
            # its exact address and interface match a root-reviewed media plan.
            known = False
            for media_file in Path('/etc/sokrat/media').glob('pbx_*/plan.json'):
                link = validate_plan(read_json(media_file))
                if (route.get('dev') == link['interface'] and destination in
                        (link['gatewayIp'],link['gatewayIp']+'/32',link['pbxIp'],link['pbxIp']+'/32')):
                    known = True;break
            if not known:raise ValueError('Media pool overlaps an existing route')
    installer = load_installer()
    installer.private_directory(ROOT)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.host)])
    try:
        san = x509.IPAddress(ipaddress.ip_address(args.host))
    except ValueError:
        san = x509.DNSName(args.host)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]),critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
                key_encipherment=False,data_encipherment=False,key_agreement=False,
                key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(key,hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    installer.write(ROOT/'server.crt',cert_pem,0o600)
    installer.write(ROOT/'server.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),0o600)
    secret = secrets.token_urlsafe(32)
    config = {'publicHost':args.host, 'mediaPool':args.pool, 'port':args.port,
              'controlPort':args.control_port, 'pluginPort':args.plugin_port,
              'tunnelPort':args.tunnel_port, 'pairingSecret':secret,
              'frpTokenFile':'/etc/sokrat/gateway-tunnel.token', 'gatewayUrl':args.gateway_url,
              'runtimePort':args.runtime_port, 'trustedStateDir':args.trusted_state_dir}
    trusted_state(config)
    token = {'v':2,'host':args.host,'port':args.port,'ca':cert_pem,'secret':secret}
    encoded = 'sk_pair_v2_' + base64.urlsafe_b64encode(json.dumps(token,separators=(',',':')).encode()).decode().rstrip('=')
    installer.write(PAIRING_FILE,encoded+'\n',0o600)
    installer.write(BRIDGE_FILE,secrets.token_urlsafe(32)+'\n',0o600)
    for file in (PAIRING_FILE,BRIDGE_FILE):
        os.chown(file,0,group);os.chmod(file,0o640)
    # The service's ConditionPathExists uses this file as its activation marker.
    # Commit it last, so an interrupted first install can retry rather than
    # appearing initialized without its pairing/bridge credentials.
    save_json(CONFIG,config)
    print('Initialized reverse TLS enrollment; pairing code stored privately')


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self,*args,tls_context=None):
        self.slots = threading.BoundedSemaphore(16)
        self.tls_context = tls_context
        super().__init__(*args)

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request);return
        try:super().process_request(request,address)
        except Exception:
            self.slots.release();raise

    def process_request_thread(self,request,address):
        try:
            request.settimeout(10)
            if self.tls_context:
                # Handshake in a bounded worker, NOT the accept loop. A TCP
                # client sending no TLS bytes cannot stall all new enrollment.
                request = self.tls_context.wrap_socket(request,server_side=True)
            super().process_request_thread(request,address)
        except (OSError,ssl.SSLError):
            self.shutdown_request(request)
        finally:self.slots.release()


def serve():
    config = read_json(CONFIG)
    worker = read_json(Path('/etc/sokrat/gateway-provisioning.json'))
    if worker.get('runtime',{}).get('trustedStateDir') != config['trustedStateDir']:
        raise ValueError('Enrollment and reconciler must share trusted allocation state')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass  # Never log request bodies, tokens or plugin metadata.

        def do_POST(self):
            try:
                self.connection.settimeout(20)
                length = int(self.headers.get('Content-Length','0'))
                if (not 0 < length <= 16384 or self.headers.get('Transfer-Encoding')
                        or len(self.headers.get_all('Content-Length',[])) != 1):
                    raise ValueError('Invalid request size')
                body = json.loads(self.rfile.read(length))
                if not isinstance(body,dict):raise ValueError('Object required')
                if self.server.server_port == config['pluginPort'] and self.path == '/firewall':
                    with LOCK:
                        response = firewall_request(config,body,self.headers.get('X-Sokrat-Tunnel-Bridge',''))
                elif self.server.server_port == config['pluginPort']:
                    with LOCK:
                        installations = read_json(REGISTRY,{})
                    operation = plugin_operation(body,self.path)
                    allowed = authorize_plugin(operation,body.get('content'),installations)
                    if allowed:
                        identity = body['content'] if operation=='Login' else body['content']['user']
                        user = identity['user']
                        # Dashboard disable/retire is never undone by a tunnel
                        # reconnect. This read may deny authority, not grant it.
                        if CONTROL.is_symlink():raise ValueError('Unsafe control file')
                        with CONTROL.open() as stream:
                            records = json.loads(stream.read(2*1024*1024))['pbx']
                        allowed = any(row['id']==user and row.get('enabled') is True
                                      and row.get('management',{}).get('approvalStatus')=='approved'
                                      for row in records)
                    response = {'reject':not allowed,'unchange':True}
                    if not allowed:response['reject_reason']='Installation or proxy scope refused'
                elif self.path == '/register':
                    response = register(config,body)
                elif self.path == '/api/gateway/incoming-call':
                    # HTTPS push entry point shares the operator-pinned gateway
                    # certificate. Runtime still verifies token/replay headers.
                    headers = {'Content-Type':'application/json'}
                    for name in ('Authorization','X-Sokrat-Pbx','X-Sokrat-Timestamp','X-Sokrat-Nonce'):
                        if self.headers.get(name):headers[name]=self.headers[name]
                    upstream = http.client.HTTPConnection('127.0.0.1',config.get('runtimePort',9097),timeout=5)
                    try:
                        upstream.request('POST','/api/gateway/incoming-call',json.dumps(body),headers)
                        result=upstream.getresponse();raw=result.read(8193)
                        if result.status!=200 or len(raw)>8192:raise ValueError('Push refused')
                        response=json.loads(raw)
                    finally:upstream.close()
                else:
                    raise ValueError('Unsupported operation')
                data = json.dumps(response).encode()
                self.send_response(200)
            except Exception:
                data = b'{"success":false,"error":"Enrollment refused; check pairing, installation credential and server approval"}'
                self.send_response(403)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
    plugin = BoundedServer(('127.0.0.1',config['pluginPort']),Handler)
    threading.Thread(target=plugin.serve_forever,daemon=True).start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(ROOT/'server.crt'),str(ROOT/'server.key'))
    server = BoundedServer(('0.0.0.0',config['port']),Handler,tls_context=context)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--init',action='store_true')
    parser.add_argument('--stage-migration',action='store_true')
    parser.add_argument('--host')
    parser.add_argument('--pool')
    parser.add_argument('--gateway-url')
    parser.add_argument('--port',type=int,default=7443)
    parser.add_argument('--control-port',type=int,default=8002)
    parser.add_argument('--plugin-port',type=int,default=7450)
    parser.add_argument('--tunnel-port',type=int,default=7000)
    parser.add_argument('--runtime-port',type=int,default=9097)
    parser.add_argument('--service-user',default='sokrat-push')
    parser.add_argument('--trusted-state-dir',default='/var/lib/sokrat-tenant-provisioning/runtime-state')
    args = parser.parse_args()
    if (any(not 1024 <= value <= 65535 for value in
            (args.port,args.control_port,args.plugin_port,args.tunnel_port,args.runtime_port))
            or len({args.port,args.control_port,args.plugin_port,args.tunnel_port,args.runtime_port}) != 5):
        raise ValueError('Distinct unprivileged service ports required')
    if os.geteuid()!=0:
        raise ValueError('Root required')
    if args.init and args.stage_migration:raise ValueError('Choose one operation')
    if args.stage_migration:
        raw = sys.stdin.read(16385)
        if len(raw)>16384:raise ValueError('Migration request too large')
        stage_migration(json.loads(raw))
    elif args.init:initialize(args)
    else:serve()


if __name__=='__main__':
    main()
