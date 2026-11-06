#!/usr/bin/env python3
"""Private SSH migration agent. JSON on stdout; never print Docker output/secrets.

Runs on a Linux Docker host as root. Archives and journals are operation-owned.
No registry pushes, profile generation, or DNS provider credentials are used.
"""
import contextlib
import base64
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path('/var/lib/amnezia/migrations')
LABEL = 'org.amnezia.migration'
NETWORK = 'amnezia-dns-net'
VOLUME = 'amnezia-connection-updates-state'
SPECS = {
    'amnezia-wireguard': ('wg', 'wg0', '/opt/amnezia/wireguard/wg0.conf'),
    'amnezia-awg2': ('awg', 'awg0', '/opt/amnezia/awg/awg0.conf'),
    'amnezia-dns': None,
    'amnezia-connection-updates': None,
}
MAX = 2 * 1024**3


class Rejected(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Rejected(reason)


def run(*args, data=None, output=None, timeout=180):
    def limit():
        maximum = MAX if output is not None else 64*1024**2
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    # stdout can contain private keys or archives: anonymous private disk storage,
    # never logs; bounded before reading into memory. Stderr is never retained.
    with tempfile.TemporaryFile() as temp:
        result = subprocess.run(['docker', *args], input=data, stdout=output if output is not None else temp,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False, preexec_fn=limit)
        require(result.returncode == 0, 'docker_command_failed_'+args[0])
        if output is not None:
            return b''
        require(temp.tell() <= 64*1024**2, 'docker_output_too_large')
        temp.seek(0)
        return temp.read()


def inspect(kind, name):
    return json.loads(run(kind, 'inspect', name))[0]


def exists(kind, name):
    return subprocess.run(['docker', kind, 'inspect', name], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    temp = path.with_suffix('.tmp')
    with open(temp, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as out:
        json.dump(value, out, sort_keys=True, separators=(',', ':'))
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def tar_hash(raw, dns=False):
    """Ignore timestamps/order; reject links/devices and duplicate paths."""
    import io
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
        for member in archive:
            path = member.name.removeprefix('./').rstrip('/')
            require(not path.startswith('/') and '..' not in path.split('/'), 'unsafe_archive')
            if member.isdir():
                continue
            if dns and path in ('unbound.pid', 'var/root.key'):
                # PID and RFC5011 trust-anchor refresh metadata are runtime state,
                # rewritten by unbound on startup; config files remain exact.
                continue
            devices = {'dev/null': (1, 3), 'dev/random': (1, 8), 'dev/urandom': (1, 9)}
            if dns and member.ischr() and devices.get(path) == (member.devmajor, member.devminor):
                result[path] = 'device:'+str(member.devmajor)+':'+str(member.devminor)
                continue
            require(member.isfile() and path not in result and member.size <= MAX, 'unsafe_archive')
            f = archive.extractfile(member)
            result[path] = hashlib.sha256(f.read()).hexdigest()
    return result


def volume_tar(helper, name):
    return run('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
               '--entrypoint', '/bin/sh', '--mount', 'type=volume,src='+name+',dst=/volume,readonly',
               helper, '-c', 'tar -C /volume -cf - .')


def live_config(container):
    tool, interface, _ = SPECS[container['Name'].lstrip('/')]
    raw = run('exec', container['Id'], tool, 'showconf', interface).decode()
    # Roaming endpoint changes are session state, never part of the peer identity.
    blocks = re.split(r'(?m)^\[Peer\]\s*$', raw)
    return sorted('\n'.join(sorted(line.strip() for line in block.splitlines()
                                   if line.strip() and not re.match(r'^\s*Endpoint\s*=', line)))
                  for block in blocks)


def state(containers, details=False, live=True):
    h = {}
    for c in containers:
        name = c['Name'].lstrip('/')
        if SPECS[name]:
            raw = run('cp', c['Id']+':/opt/amnezia/.', '-')
            h[name] = {'files': tar_hash(raw)}
            if live:
                h[name]['live'] = hashlib.sha256(json.dumps(live_config(c)).encode()).hexdigest()
        elif name == 'amnezia-dns':
            h[name] = tar_hash(run('cp', c['Id']+':/opt/unbound/etc/unbound/.', '-'), dns=True)
    helper = next(c['Image'] for c in containers if SPECS[c['Name'].lstrip('/')])
    if any(c['Name'] == '/amnezia-connection-updates' for c in containers):
        h['delivery'] = tar_hash(volume_tar(helper, VOLUME))
    return h if details else hashlib.sha256(json.dumps(h, sort_keys=True).encode()).hexdigest()


def inventory():
    ids = run('container', 'ls', '-aq', '--no-trunc').decode().split()
    containers = json.loads(run('container', 'inspect', *ids)) if ids else []
    active = [c for c in containers if c['State']['Running']]
    require(not any(c['Name'].startswith('/amnezia-') and c['Name'][1:] not in SPECS
                    for c in active), 'unsupported_active_stack')
    chosen = [c for c in active if c['Name'][1:] in SPECS]
    require(any(SPECS[c['Name'][1:]] for c in chosen), 'no_running_vpn')
    for c in chosen:
        name, hc = c['Name'][1:], c['HostConfig']
        require(hc['NetworkMode'] not in ('host', 'none') and
                not hc['NetworkMode'].startswith('container:'), 'custom_network')
        require(set(c['NetworkSettings']['Networks']) <= {'bridge', NETWORK}, 'custom_network')
        require(not hc.get('Devices') and not hc.get('VolumesFrom') and not hc.get('Links'), 'custom_mounts')
        require(not hc.get('AutoRemove'), 'auto_remove_container')
        require(hc['RestartPolicy']['Name'] in ('always', 'unless-stopped', 'no'), 'unsupported_restart_policy')
        for mount in c['Mounts']:
            require((mount['Type'] == 'bind' and mount['Source'] == '/lib/modules' and
                     mount['Destination'] == '/lib/modules') or
                    (name == 'amnezia-connection-updates' and mount['Type'] == 'volume' and
                     mount['Name'] == VOLUME and mount['Destination'] == '/data') or
                    (name == 'amnezia-connection-updates' and mount['Type'] == 'tmpfs' and
                     mount['Destination'] == '/run/amnezia-updates' and
                     set(hc.get('Tmpfs', {}).get('/run/amnezia-updates', '').split(',')) ==
                     {'rw', 'nosuid', 'nodev', 'noexec', 'size=2m', 'mode=0700'}), 'custom_mounts')
        if name == 'amnezia-connection-updates':
            require(c['Config'].get('Labels', {}).get('org.amnezia.connection-updates') == '1', 'unowned_delivery')
            volume = inspect('volume', VOLUME)
            require(volume['Driver'] == 'local' and not volume.get('Options') and
                    (volume.get('Labels') or {}).get('org.amnezia.connection-updates') == '1', 'custom_delivery_volume')
            info = json.loads(run('exec', c['Id'], '/updates', 'info'))
            require(info.get('host') and not is_ip(info['host']), 'delivery_requires_domain')
    return chosen


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def network_spec():
    if not exists('network', NETWORK):
        return None
    n = inspect('network', NETWORK)
    require(n['Driver'] == 'bridge' and not n['Internal'] and not n.get('EnableIPv6'), 'custom_dns_network')
    require(n['IPAM']['Config'] == [{'Subnet': '172.29.172.0/24', 'Gateway': '172.29.172.1'}], 'custom_dns_network')
    return {'Name': NETWORK, 'Driver': 'bridge', 'IPAM': n['IPAM'],
            'Options': n.get('Options') or {}, 'Labels': n.get('Labels') or {}}


def prepare_source(work, journal):
    require(not journal, 'operation_already_exists')
    require(shutil.disk_usage(work).free >= 3*MAX, 'insufficient_snapshot_space')
    containers = inventory()
    before = state(containers)
    delivery = next((c for c in containers if c['Name'] == '/amnezia-connection-updates'), None)
    delivery_info = json.loads(run('exec', delivery['Id'], '/updates', 'info')) if delivery else {}
    delivery_host = delivery_info.get('host', '')
    manifest = {'deliveryInfo': delivery_info, 'deliveryHost': delivery_host, 'version': 1, 'architecture': json.loads(run('info', '--format', '{{json .Architecture}}')),
                'containers': containers, 'network': network_spec(), 'state': before, 'checks': state(containers, details=True), 'images': {},
                'volume': any(c['Name'] == '/amnezia-connection-updates' for c in containers)}
    save(work/'journal.json', {'role': 'source', 'phase': 'copying', 'manifest': manifest})
    # docker commit pauses only the selected container and unpauses it itself.
    # Check persistent/live state on both sides of the snapshot window.
    for c in containers:
        image = run('commit', c['Id']).decode().strip()
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', image), 'invalid_snapshot_image_id')
        manifest['images'][c['Name'][1:]] = image
        save(work/'journal.json', {'role': 'source', 'phase': 'copying', 'manifest': manifest})
        # No tag is created and nothing is ever pushed to a registry.
    with open(work/'images.tar', 'xb') as f:
        run('image', 'save', *manifest['images'].values(), output=f, timeout=1200)
    if manifest['volume']:
        helper = next(manifest['images'][c['Name'][1:]] for c in containers if SPECS[c['Name'][1:]])
        (work/'volume.tar').write_bytes(volume_tar(helper, VOLUME))
    require(state(containers) == before, 'source_changed_during_snapshot')
    save(work/'manifest.json', manifest)
    with tarfile.open(work/'bundle.tar', 'x') as bundle:
        for name in ['manifest.json', 'images.tar'] + (['volume.tar'] if manifest['volume'] else []):
            require((work/name).stat().st_size < MAX, 'bundle_too_large')
            bundle.add(work/name, arcname=name, recursive=False)
    require((work/'bundle.tar').stat().st_size <= MAX, 'bundle_too_large')
    journal = {'role': 'source', 'phase': 'exported', 'manifest': manifest,
               'sha256': digest(work/'bundle.tar'), 'bytes': (work/'bundle.tar').stat().st_size}
    save(work/'journal.json', journal)
    return journal


class DockerHTTP(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost', timeout=120)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect('/var/run/docker.sock')


def api(path, value):
    with contextlib.closing(DockerHTTP()) as conn:
        conn.request('POST', '/v1.45'+path, json.dumps(value), {'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read()
        require(response.status in (200, 201, 204), 'docker_api_failed')
        return json.loads(raw) if raw else {}


def unpack(work, expected):
    require(digest(work/'incoming.tar') == expected, 'bundle_digest_mismatch')
    seen = set()
    with tarfile.open(work/'incoming.tar', 'r:') as bundle:
        for item in bundle:
            require(item.name in ('manifest.json', 'images.tar', 'volume.tar') and item.isfile()
                    and item.name not in seen and item.size <= MAX, 'unsafe_archive')
            seen.add(item.name)
            with open(work/item.name, 'xb') as out:
                source = bundle.extractfile(item)
                for block in iter(lambda: source.read(65536), b''):
                    out.write(block)
    require({'manifest.json', 'images.tar'} <= seen, 'incomplete_bundle')
    manifest = json.loads((work/'manifest.json').read_bytes())
    require(manifest['version'] == 1, 'unsupported_bundle')
    require(not manifest['volume'] or 'volume.tar' in seen, 'incomplete_bundle')
    return manifest


def validate_target(m):
    require(m['architecture'] == json.loads(run('info', '--format', '{{json .Architecture}}')), 'architecture_mismatch')
    require(not exists('network', NETWORK) and not exists('volume', VOLUME), 'target_resource_collision')
    for c in m['containers']:
        name = c['Name'].lstrip('/')
        require(name in SPECS and not exists('container', name), 'target_container_collision')
        for port, bindings in (c['HostConfig'].get('PortBindings') or {}).items():
            number, protocol = port.split('/')
            for binding in bindings or []:
                # Check host-level collisions as well as Docker's own port checks.
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM)
                try:
                    sock.bind(('0.0.0.0', int(binding['HostPort'] or number)))
                except OSError:
                    raise Rejected('target_port_collision')
                finally:
                    sock.close()


def restore_volume(work, m):
    helper = next(m['images'][c['Name'][1:]] for c in m['containers'] if SPECS[c['Name'][1:]])
    raw = (work/'volume.tar').read_bytes()
    tar_hash(raw)  # Validate all entries before any write, including traversal/links.
    run('run', '--rm', '-i', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--entrypoint', '/bin/sh', '--mount', 'type=volume,src='+VOLUME+',dst=/volume',
        helper, '-c', 'tar -C /volume -xf -', data=raw)


def import_target(work, journal, req):
    require(not journal, 'operation_already_exists')
    require(shutil.disk_usage(work).free >= 3*MAX, 'insufficient_import_space')
    m = unpack(work, req['sha256'])
    validate_target(m)
    journal = {'role': 'target', 'phase': 'importing', 'manifest': m, 'containers': [],
               'network': False, 'volume': False}
    save(work/'journal.json', journal)
    with open(work/'images.tar', 'rb') as f:
        p = subprocess.run(['docker', 'image', 'load', '--quiet'], stdin=f,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
        require(p.returncode == 0, 'image_load_failed')
    if m['network']:
        n = dict(m['network'])
        n['Labels'] = {**n['Labels'], LABEL: work.name}
        api('/networks/create', n)
        journal['network'] = True
        save(work/'journal.json', journal)
    if m['volume']:
        run('volume', 'create', '--label', LABEL+'='+work.name, '--label', 'org.amnezia.connection-updates=1', VOLUME)
        require((inspect('volume', VOLUME).get('Labels') or {}).get(LABEL) == work.name, 'target_volume_ownership_changed')
        journal['volume'] = True
        save(work/'journal.json', journal)
        restore_volume(work, m)
    # DNS is started before VPNs. Delivery is read-only; ack receipts are fresh tmpfs.
    ordered = sorted(m['containers'], key=lambda c: c['Name'] != '/amnezia-dns')
    for c in ordered:
        config = dict(c['Config'])
        config['Image'] = m['images'][c['Name'][1:]]
        config['Labels'] = {**(config.get('Labels') or {}), LABEL: work.name}
        hc = dict(c['HostConfig'])
        hc['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
        hc.pop('ContainerIDFile', None)
        config['HostConfig'] = hc
        networks = {}
        for name, endpoint in c['NetworkSettings']['Networks'].items():
            networks[name] = {'IPAMConfig': endpoint.get('IPAMConfig')}
        config['NetworkingConfig'] = {'EndpointsConfig': networks}
        created = api('/containers/create?name='+c['Name'][1:], config)['Id']
        journal['containers'].append(created)
        save(work/'journal.json', journal)
        run('start', created)
    journal['phase'] = 'staged'
    save(work/'journal.json', journal)
    return verify_target(work, journal)


def owned(journal, work):
    result = []
    for cid in journal['containers']:
        c = inspect('container', cid)
        require(c['Config']['Labels'].get(LABEL) == work.name, 'ownership_changed')
        result.append(c)
    return result


def delivery_https_probe(info, address):
    certificate = base64.b64decode(info['certificate'], validate=True)
    context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(certificate))
    with socket.create_connection((str(ipaddress.ip_address(address)), 8443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=info['host']) as tls:
            require(tls.getpeercert(binary_form=True) == certificate, 'delivery_certificate_changed')
            tls.sendall(b'GET /migration-connectivity-check HTTP/1.1\r\nHost: '+info['host'].encode()+b'\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(tls)
            response.begin()
            require(response.status == 404, 'delivery_http_probe_failed')


def verify_target(work, journal):
    require(journal.get('role') == 'target' and journal['phase'] in ('staged', 'validated', 'ready', 'active'), 'wrong_phase')
    require(not journal.get('probes'), 'probe_cleanup_required')
    containers = owned(journal, work)
    for c in containers:
        require(c['State']['Running'], 'target_not_running')
        spec = SPECS[c['Name'][1:]]
        if spec:
            # Wait for startup script and interface creation, bounded to 20 seconds.
            for attempt in range(20):
                try:
                    live_config(c)
                    break
                except Rejected:
                    if attempt == 19:
                        raise
                    time.sleep(1)
        if c['Name'] == '/amnezia-connection-updates':
            info = json.loads(run('exec', c['Id'], '/updates', 'info'))
            for key in ('host', 'certificate', 'publicKey'):
                require(info[key] == journal['manifest']['deliveryInfo'][key], 'delivery_identity_changed')
            delivery_https_probe(info, '127.0.0.1')
        if c['Name'] == '/amnezia-dns':
            require(c['NetworkSettings']['Networks'][NETWORK]['IPAddress'] == '172.29.172.254', 'dns_address_changed')
            run('exec', c['Id'], '/opt/unbound/sbin/unbound-checkconf')
    require(state(containers) == journal['manifest']['state'], 'target_state_mismatch')
    journal['phase'] = journal['phase'] if journal['phase'] in ('ready', 'active') else 'validated'
    save(work/'journal.json', journal)
    return journal


def source_containers(journal):
    result = []
    for original in journal['manifest']['containers']:
        c = inspect('container', original['Id'])
        require(c['Name'] == original['Name'] and c['Image'] == original['Image'], 'source_identity_changed')
        result.append(c)
    return result


def persisted_checks(containers):
    return state(containers, details=True, live=False)


def expected_persisted_checks(journal):
    expected = json.loads(json.dumps(journal['manifest']['checks']))
    for value in expected.values():
        if isinstance(value, dict):
            value.pop('live', None)
    return expected


def source_action(work, journal, action):
    require(journal.get('role') == 'source', 'wrong_role')
    cs = source_containers(journal)
    if action == 'source-check':
        require({c['Id'] for c in inventory()} == {c['Id'] for c in cs}, 'source_stack_changed')
        require(journal['phase'] == 'exported' and all(c['State']['Running'] for c in cs), 'source_not_running')
        require(state(cs) == journal['manifest']['state'], 'source_changed')
    elif action == 'source-stop':
        require(journal['phase'] in ('exported', 'stopping', 'stopped'), 'wrong_phase')
        if journal['phase'] in ('stopping', 'stopped'):
            require(persisted_checks(cs) == expected_persisted_checks(journal), 'source_changed')
        if journal['phase'] == 'stopping':
            for c in cs:
                if c['State']['Running'] and SPECS[c['Name'][1:]]:
                    current = hashlib.sha256(json.dumps(live_config(c)).encode()).hexdigest()
                    require(current == journal['manifest']['checks'][c['Name'][1:]]['live'], 'source_changed')
        if journal['phase'] == 'stopped':
            require(all(not c['State']['Running'] for c in cs), 'source_not_stopped')
            return journal
        if journal['phase'] == 'exported':
            require({c['Id'] for c in inventory()} == {c['Id'] for c in cs}, 'source_stack_changed')
            require(state(cs) == journal['manifest']['state'], 'source_changed')
        # Persist intent before stopping; retry/status can distinguish partial cutover.
        journal['phase'] = 'stopping'
        save(work/'journal.json', journal)
        for c in cs:
            run('update', '--restart=no', c['Id'])
            run('stop', c['Id'])
        journal['phase'] = 'stopped'
        save(work/'journal.json', journal)
    elif action == 'source-start':
        require(journal['phase'] in ('stopping', 'stopped', 'exported'), 'wrong_phase')
        current = state(cs, details=True, live=False)
        expected = json.loads(json.dumps(journal['manifest']['checks']))
        for value in expected.values():
            if isinstance(value, dict):
                value.pop('live', None)
        if journal.get('deliveryRestored'):
            current.pop('delivery', None)
            expected.pop('delivery', None)
        require(current == expected, 'source_files_changed_manual_recovery_required')
        for c in cs:
            policy = c['HostConfig']['RestartPolicy'] if journal['phase'] == 'exported' else next(
                old['HostConfig']['RestartPolicy'] for old in journal['manifest']['containers'] if old['Id'] == c['Id'])
            run('update', '--restart='+policy['Name'], c['Id'])
            if not c['State']['Running']:
                run('start', c['Id'])
        journal['phase'] = 'exported'
        save(work/'journal.json', journal)
    return journal


def target_stop(work, journal):
    require(journal.get('role') == 'target', 'wrong_role')
    journal['phase'] = 'target-stopping'
    save(work/'journal.json', journal)
    for c in owned(journal, work):
        run('update', '--restart=no', c['Id'])
        run('stop', c['Id'])
    journal['phase'] = 'stopped'
    save(work/'journal.json', journal)
    return journal


def probe_create(work, journal, req):
    require(journal.get('role') == 'target' and journal['phase'] in ('validated', 'ready'), 'wrong_phase')
    require(not journal.get('probes'), 'probe_cleanup_required')
    configs = []
    for c in owned(journal, work):
        spec = SPECS[c['Name'][1:]]
        if not spec:
            continue
        tool, interface, path = spec
        raw = run('exec', c['Id'], 'cat', path).decode()
        head = raw.split('[Peer]')[0]
        fields = dict(re.findall(r'(?m)^\s*(\w+)\s*=\s*(.*?)\s*$', head))
        address = ipaddress.ip_interface(fields['Address'].split(',')[0].strip())
        require(address.version == 4 and address.network.num_addresses <= 65536, 'unsupported_probe_subnet')
        taken = [ipaddress.ip_network(x.strip(), strict=False) for line in
                 run('exec', c['Id'], tool, 'show', interface, 'allowed-ips').decode().splitlines()
                 for x in line.split('\t', 1)[1].split() if x != '(none)']
        free = next((a for a in reversed(list(address.network.hosts())) if a != address.ip
                     and not any(a in network for network in taken)), None)
        require(free is not None, 'no_probe_address')
        private = run('exec', c['Id'], tool, 'genkey').strip()
        public_key = run('exec', '-i', c['Id'], tool, 'pubkey', data=private+b'\n').decode().strip()
        server_key = run('exec', c['Id'], tool, 'show', interface, 'public-key').decode().strip()
        # Journal before mutation; probe-remove recovers an interrupted attempt.
        probe = {'id': c['Id'], 'tool': tool, 'interface': interface, 'publicKey': public_key}
        journal.setdefault('probes', []).append(probe)
        save(work/'journal.json', journal)
        run('exec', c['Id'], tool, 'set', interface, 'peer', public_key, 'allowed-ips', str(free)+'/32')
        parameters = ''.join(k+' = '+v+'\n' for k, v in fields.items()
                             if k not in ('PrivateKey', 'Address', 'ListenPort', 'SaveConfig', 'DNS',
                                          'PreUp', 'PostUp', 'PreDown', 'PostDown', 'Table', 'MTU'))
        endpoint = str(ipaddress.ip_address(req['address']))
        require(':' not in endpoint, 'probe_requires_ipv4_target')
        dns = ',172.29.172.254/32' if any(x['Name'] == '/amnezia-dns' for x in journal['manifest']['containers']) else ''
        config = ('[Interface]\nPrivateKey = '+private.decode()+'\nAddress = '+str(free)+'/32\n'+parameters+
                  '[Peer]\nPublicKey = '+server_key+'\nAllowedIPs = '+str(address.ip)+'/32'+dns+
                  '\nEndpoint = '+endpoint+':'+fields['ListenPort']+'\nPersistentKeepalive = 1\n')
        configs.append({'name': c['Name'][1:], 'config': config, 'ping': str(address.ip), 'dns': bool(dns)})
    return {'version': 1, 'configs': configs}


def probe_remove(work, journal):
    for p in journal.get('probes', []):
        c = inspect('container', p['id'])
        require(c['Config']['Labels'].get(LABEL) == work.name, 'ownership_changed')
        run('exec', p['id'], p['tool'], 'set', p['interface'], 'peer', p['publicKey'], 'remove')
    journal['probes'] = []
    save(work/'journal.json', journal)
    return journal


def cleanup_probe_clients(work):
    ids = run('container', 'ls', '-aq', '--filter', 'label='+LABEL+'.probe='+work.name).decode().split()
    for cid in ids:
        c = inspect('container', cid)
        require((c['Config'].get('Labels') or {}).get(LABEL+'.probe') == work.name, 'probe_ownership_changed')
        run('rm', '-f', cid)


def probe_run(work, journal, req):
    require(journal.get('role') == 'source' and journal['phase'] == 'exported', 'wrong_phase')
    cleanup_probe_clients(work)
    for probe in req['configs']:
        require(probe['name'] in journal['manifest']['images'] and SPECS.get(probe['name']), 'invalid_probe')
        tool = SPECS[probe['name']][0]
        require(len(probe['config']) < 8192, 'invalid_probe')
        ping = str(ipaddress.ip_address(probe['ping']))
        # No host network/host mount: a fresh client namespace traverses the actual
        # source egress and target's published UDP port. Its private key is temporary.
        script = ('umask 077; cat > /tmp/mprobe.conf; '+tool+'-quick up /tmp/mprobe.conf >/dev/null 2>&1; '
                  'for i in 1 2 3 4 5; do ping -c 1 -W 2 '+ping+' >/dev/null 2>&1 && break; sleep 1; done; '
                  'ping -c 2 -W 2 '+ping+' >/dev/null 2>&1')
        if probe['dns']:
            script += '; nslookup -type=soa . 172.29.172.254 >/dev/null 2>&1'
        try:
            run('run', '--rm', '-i', '--privileged', '--label', LABEL+'.probe='+work.name,
                '--entrypoint', '/bin/sh', journal['manifest']['images'][probe['name']], '-ec', script,
                data=probe['config'].encode(), timeout=60)
        finally:
            cleanup_probe_clients(work)
    info = journal['manifest'].get('deliveryInfo')
    if info:
        delivery_https_probe(info, req['address'])
    return {'version': 1, 'phase': 'probe-passed'}


def compatible_store(previous, latest):
    for key in ('host', 'signingKey', 'certificate', 'tlsKey'):
        require(latest.get(key) == previous.get(key), 'delivery_identity_changed')
    for rid, before in previous['records'].items():
        after = latest.get('records', {}).get(rid)
        require(after is not None, 'rollback_would_drop_subscription')
        require(all(after.get(k) == before.get(k) for k in ('id', 'tokenHash', 'clientPublicKey', 'container')), 'subscription_identity_changed')
        require(type(after['revision']) is int and before['revision'] <= after['revision'] <= 2**64-1, 'rollback_would_lower_revision')
        require(not before['revoked'] or after['revoked'], 'rollback_would_unrevoke_subscription')


def state_from_tar(raw):
    import io
    files = tar_hash(raw)
    require('state.json' in files and set(files) <= {'state.json', '.lock'}, 'invalid_rollback_store')
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        member = next(m for m in archive if m.name.removeprefix('./') == 'state.json')
        require(member.size <= 4*1024**2, 'invalid_rollback_store')
        return json.loads(archive.extractfile(member).read())


def rollback_export(work, journal):
    require(journal.get('role') == 'target' and journal['phase'] in ('active', 'target-stopping', 'stopped', 'rollback-exported'), 'wrong_phase')
    if journal['manifest']['volume']:
        helper = next(journal['manifest']['images'][c['Name'][1:]] for c in journal['manifest']['containers'] if SPECS[c['Name'][1:]])
        compatible_store(state_from_tar((work/'volume.tar').read_bytes()), state_from_tar(volume_tar(helper, VOLUME)))
    if journal['phase'] == 'active':
        checks = state(owned(journal, work), details=True)
        expected = dict(journal['manifest']['checks'])
        checks.pop('delivery', None)
        expected.pop('delivery', None)
        require(checks == expected, 'target_vpn_or_dns_changed_manual_recovery_required')
        target_stop(work, journal)
    elif journal['phase'] == 'target-stopping':
        checks = persisted_checks(owned(journal, work))
        expected = expected_persisted_checks(journal)
        checks.pop('delivery', None)
        expected.pop('delivery', None)
        require(checks == expected, 'target_vpn_or_dns_changed_manual_recovery_required')
        target_stop(work, journal)
    if journal['manifest']['volume']:
        helper = next(journal['manifest']['images'][c['Name'][1:]] for c in journal['manifest']['containers'] if SPECS[c['Name'][1:]])
        raw = volume_tar(helper, VOLUME)
        tar_hash(raw)
        (work/'rollback.tar').write_bytes(raw)
        os.chmod(work/'rollback.tar', 0o600)
        journal['rollback'] = {'file': str(work/'rollback.tar'), 'sha256': digest(work/'rollback.tar'), 'bytes': len(raw)}
    journal['phase'] = 'rollback-exported'
    save(work/'journal.json', journal)
    return journal


def rollback_import(work, journal, req):
    require(journal.get('role') == 'source' and journal['phase'] in ('stopped', 'stopping'), 'wrong_phase')
    require(all(not c['State']['Running'] for c in source_containers(journal)), 'source_not_stopped')
    path = Path('/tmp/amnezia-migration-'+work.name)/'rollback.tar'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 8*1024**2, 'invalid_rollback_store')
    require(digest(path) == req['sha256'], 'rollback_digest_mismatch')
    raw = path.read_bytes()
    latest = state_from_tar(raw)
    volume = inspect('volume', VOLUME)
    require(volume['Driver'] == 'local' and not volume.get('Options') and
            (volume.get('Labels') or {}).get('org.amnezia.connection-updates') == '1', 'custom_delivery_volume')
    directory = Path(volume['Mountpoint'])
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(), 'custom_delivery_volume')
    with os.fdopen(os.open(directory/'.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not (directory/'state.json').is_symlink(), 'invalid_delivery_state')
        previous = json.loads((directory/'state.json').read_bytes())
        compatible_store(previous, latest)
        save(directory/'state.json', latest)
    journal['deliveryRestored'] = req['sha256']
    save(work/'journal.json', journal)
    return journal


def abort(work, journal):
    if journal.get('role') == 'source':
        cleanup_probe_clients(work)
        if journal['phase'] in ('stopping', 'stopped'):
            source_action(work, journal, 'source-start')
        else:
            require(journal['phase'] in ('copying', 'exported', 'aborted'), 'wrong_phase')
            require(all(c['State']['Running'] for c in source_containers(journal)), 'source_not_running')
    else:
        if journal.get('manifest', {}).get('volume') and exists('volume', VOLUME):
            volume = inspect('volume', VOLUME)
            if (volume.get('Labels') or {}).get(LABEL) == work.name:
                helper = next(journal['manifest']['images'][c['Name'][1:]] for c in journal['manifest']['containers'] if SPECS[c['Name'][1:]])
                require(tar_hash(volume_tar(helper, VOLUME)) == journal['manifest']['checks']['delivery'], 'target_subscriptions_changed_manual_recovery_required')
        # Recover even if SSH vanished between create and journal update. Only
        # resources with this unpredictable operation label can be removed.
        ids = run('container', 'ls', '-aq', '--filter', 'label='+LABEL+'='+work.name).decode().split()
        for cid in ids:
            c = inspect('container', cid)
            require(c['Config']['Labels'].get(LABEL) == work.name, 'ownership_changed')
            run('rm', '-f', cid)
        for kind, name in [('network', NETWORK), ('volume', VOLUME)]:
            if exists(kind, name) and (inspect(kind, name).get('Labels') or {}).get(LABEL) == work.name:
                run(kind, 'rm', name)
    if journal.get('role') != 'source':
        journal['containers'] = []
    journal['phase'] = 'aborted'
    save(work/'journal.json', journal)
    return journal


def client_stage(operation):
    return Path('/tmp/amnezia-migration-'+operation)


def finalize(work, journal):
    require(not journal or journal.get('phase') in ('active', 'stopped', 'rollback-exported', 'aborted', 'exported', 'finalized'), 'unfinished_operation')
    # A detached worker/its starter owns this lock. Never remove its SSH files or
    # private request while it may still be using them.
    with open(work/'relay.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected('pull_job_busy')
        request = work/'pull-job/request.json'
        # Covers the tiny spawn-to-lock/PID-record window as well as a worker
        # surviving its starter. After reboot no matching process exists.
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                argv = (entry/'cmdline').read_bytes().split(b'\0')
            except (OSError, PermissionError):
                continue
            require(not any(argv[i:i+2] == [b'--worker', os.fsencode(request)]
                            for i in range(len(argv)-1)), 'pull_job_busy')
        request.unlink(missing_ok=True)
        (work/'pull-job/request.tmp').unlink(missing_ok=True)
        stage = client_stage(work.name)
        if stage.is_dir() and not stage.is_symlink():
            cache = stage/'__pycache__'
            if cache.is_dir() and not cache.is_symlink():
                shutil.rmtree(cache)
            for private in stage.glob('request-*.json'):
                if private.is_file() or private.is_symlink():
                    private.unlink()
        for stale in work.glob('ssh-*'):
            if stale.is_dir() and not stale.is_symlink():
                shutil.rmtree(stale)
        for name in ('bundle.tar', 'images.tar', 'incoming.tar', 'volume.tar', 'rollback.tar', 'manifest.json'):
            (work/name).unlink(missing_ok=True)
        if journal.get('role') == 'source':
            for image in journal.get('manifest', {}).get('images', {}).values():
                require(re.fullmatch('sha256:[a-f0-9]{64}', image), 'invalid_snapshot_image_id')
                subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        audit = {'role': journal.get('role'), 'phase': 'finalized'}
        save(work/'journal.json', audit)
        return audit


def public(journal, work):
    m = journal.get('manifest', {})
    result = {'version': 1, 'phase': journal.get('phase'), 'role': journal.get('role'),
              'containers': [c['Name'][1:] for c in m.get('containers', [])],
              'deliveryRestored': journal.get('deliveryRestored'),
              'state': m.get('state'), 'architecture': m.get('architecture'), 'deliveryHost': m.get('deliveryHost', '')}
    if journal.get('rollback'):
        result.update(journal['rollback'])
    if journal.get('sha256'):
        result.update({'sha256': journal['sha256'], 'bytes': journal['bytes'], 'file': str(work/'bundle.tar')})
    return result


def main(req):
    require(os.geteuid() == 0, 'root_required')
    operation = req.get('operation', '')
    require(re.fullmatch('[a-f0-9]{32}', operation), 'invalid_operation')
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ROOT, 0o700)
    work = ROOT/operation
    work.mkdir(mode=0o700, exist_ok=True)
    # Match the protocol updater/rollout locks, plus one host-wide migration lock.
    locks = []
    try:
        for path in [ROOT/'lock', Path('/var/lib/amnezia/updates/amnezia-wireguard.lock'),
                     Path('/var/lib/amnezia/updates/amnezia-awg2.lock')]:
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            lock = open(path, 'a')
            locks.append(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Rejected('maintenance_busy')
        journal = json.loads((work/'journal.json').read_bytes()) if (work/'journal.json').exists() else {}
        action = req.get('action')
        if action == 'receive':
            require(not journal, 'operation_already_exists')
            incoming = Path('/tmp/amnezia-migration-'+operation)/'incoming.tar'
            require(incoming.is_file() and not incoming.is_symlink() and incoming.stat().st_size <= MAX, 'invalid_upload')
            with open(incoming, 'rb') as source, open(work/'incoming.tar', 'xb') as out:
                import shutil
                shutil.copyfileobj(source, out, 65536)
            return {'version': 1, 'phase': 'received'}
        if action == 'export':
            journal = prepare_source(work, journal)
        elif action == 'import':
            journal = import_target(work, journal, req)
        elif action == 'probe-create':
            return probe_create(work, journal, req)
        elif action == 'probe-run':
            return probe_run(work, journal, req)
        elif action == 'probe-confirm':
            verify_target(work, journal)
            require(journal['phase'] in ('validated', 'ready'), 'wrong_phase')
            journal['phase'] = 'ready'
            save(work/'journal.json', journal)
        elif action == 'probe-remove':
            journal = probe_remove(work, journal)
        elif action == 'verify':
            journal = verify_target(work, journal)
        elif action in ('source-check', 'source-stop', 'source-start'):
            journal = source_action(work, journal, action)
        elif action == 'rollback-export':
            journal = rollback_export(work, journal)
        elif action == 'rollback-import':
            journal = rollback_import(work, journal, req)
        elif action == 'abort':
            journal = abort(work, journal)
        elif action == 'target-stop':
            journal = target_stop(work, journal)
        elif action == 'activate':
            require(journal.get('phase') in ('ready', 'active'), 'external_probe_required')
            verify_target(work, journal)
            for c in owned(journal, work):
                old = next(x for x in journal['manifest']['containers'] if x['Name'] == c['Name'])
                run('update', '--restart='+old['HostConfig']['RestartPolicy']['Name'], c['Id'])
            journal['phase'] = 'active'
            save(work/'journal.json', journal)
        elif action == 'finalize':
            journal = finalize(work, journal)
        elif action == 'status':
            if not journal:
                return {'version': 1, 'phase': 'absent', 'role': 'none'}
        else:
            raise Rejected('invalid_action')
        result = public(journal, work)
        if action == 'status':
            if journal.get('role') == 'source' and journal.get('manifest'):
                cs = source_containers(journal)
                expected = {c['Id']: c['HostConfig']['RestartPolicy'] for c in journal['manifest']['containers']}
                result['restartPoliciesRestored'] = all(c['HostConfig']['RestartPolicy'] == expected[c['Id']] for c in cs)
            elif journal.get('role') == 'target' and journal.get('manifest'):
                cs = owned(journal, work)
            else:
                cs = []
            result['running'] = {c['Name'][1:]: c['State']['Running'] for c in cs}
        return result
    finally:
        for lock in locks:
            lock.close()


if __name__ == '__main__':
    os.umask(0o077)
    try:
        import base64
        request = json.loads(base64.b64decode(sys.argv[1], validate=True) if len(sys.argv) == 2
                             else sys.stdin.buffer.read(65537))
        result = main(request)
        print(json.dumps({'ok': True, **result}))
    except (Rejected, OSError, ValueError, KeyError, StopIteration, subprocess.TimeoutExpired, tarfile.TarError) as error:
        # Fail closed. Transport loss or an exception after intent was journaled
        # requires status/recovery, never a guessed success or automatic deletion.
        reason = str(error) if isinstance(error, Rejected) else 'agent_failed_check_status'
        print(json.dumps({'ok': False, 'reason': reason}))
        sys.exit(1)
