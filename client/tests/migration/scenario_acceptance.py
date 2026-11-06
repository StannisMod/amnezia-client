#!/usr/bin/env python3
"""Two disposable Docker hosts, real WG/AWG traffic, DNS and signed subscriptions.

Run only through scripts/local-tests/migration-scenario.sh, never on a real VPS.
The outer Docker daemon only receives labelled fixture containers/volumes/network.
All production-like resource names are inside the two nested daemons.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO/'client/server_scripts'
AGENT = '/src/client/server_scripts/migration/agent.py'
TOKEN = uuid.uuid4().hex[:12]
NETWORK = 'amnezia-migration-test-'+TOKEN
HOSTS = {side: 'amnezia-migration-test-'+TOKEN+'-'+side for side in ('source', 'target')}
OP = uuid.uuid4().hex


def cmd(*args, data=None, binary=False, check=True):
    r = subprocess.run(args, input=data, capture_output=True, text=not binary)
    if check and r.returncode:
        raise RuntimeError('Test command failed: '+str(args[:5])+'\n'+str(r.stderr)[-1800:])
    return r.stdout if check else r


def host(side, *args, data=None, binary=False):
    return cmd('docker', 'exec', '-i', HOSTS[side], *args, data=data, binary=binary)


def d(side, *args, data=None, binary=False):
    return host(side, 'docker', *args, data=data, binary=binary)


def agent(side, action, expect=True, **extra):
    raw = json.dumps({'operation': OP, 'action': action, **extra})
    r = cmd('docker', 'exec', '-i', HOSTS[side], 'python3', AGENT, data=raw, check=False)
    result = json.loads(r.stdout)
    if expect:
        if r.returncode or not result['ok']:
            diagnostic = host(side, 'python3', '-c',
                              'import json,pathlib; p=pathlib.Path("/var/lib/amnezia/migrations/'+OP+'/journal.json"); print(json.loads(p.read_bytes()).get("phase") if p.exists() else "absent")')
            raise AssertionError(str(result)+' phase='+diagnostic)
    else:
        assert not result['ok'], result
    return result


def copy(side, text, path, mode='600'):
    host(side, 'sh', '-ec', 'umask 077; cat > "$1"; chmod "$2" "$1"', 'sh', path, mode, data=text)


def setup():
    cmd('docker', 'network', 'create', '--label', 'org.amnezia.migration.test='+TOKEN, NETWORK)
    for side, name in HOSTS.items():
        cmd('docker', 'run', '-d', '--privileged', '--name', name, '--network', NETWORK,
            '--label', 'org.amnezia.migration.test='+TOKEN, '--dns', '1.1.1.1', '--dns', '8.8.8.8', '-e', 'DOCKER_TLS_CERTDIR=',
            '--mount', 'type=bind,source='+str(REPO)+',target=/src,readonly',
            '--mount', 'type=bind,source=/lib/modules,target=/lib/modules,readonly',
            '--mount', 'type=volume,source=amnezia-migration-acceptance-'+side+',target=/var/lib/docker',
            'amnezia-local-vpn-tests', 'dockerd', '--host=unix:///var/run/docker.sock',
            '--dns=1.1.1.1', '--dns=8.8.8.8', '--label', 'amnezia.test-environment=disposable')
        for _ in range(60):
            r = cmd('docker', 'exec', name, 'docker', 'info', check=False)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Nested daemon failed to start')
        # A prior interrupted run may have left synthetic resources in our volume.
        # Assert daemon label before resetting only this dedicated test environment.
        assert 'amnezia.test-environment=disposable' in json.loads(d(side, 'info', '--format', '{{json .Labels}}'))
        ids = d(side, 'ps', '-aq').split()
        if ids:
            d(side, 'rm', '-f', *ids)
        nets = d(side, 'network', 'ls', '--filter', 'type=custom', '-q').split()
        if nets:
            d(side, 'network', 'rm', *nets)
        vols = d(side, 'volume', 'ls', '-q').split()
        if vols:
            d(side, 'volume', 'rm', *vols)


def ready(name, tool, interface):
    for _ in range(35):
        r = cmd('docker', 'exec', HOSTS['source'], 'docker', 'exec', name, tool, 'show', interface, check=False)
        if r.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError('VPN startup failed')


def fixture(header_protection=False):
    # Real production Dockerfiles. Force the AWG userspace implementation so a
    # host kernel module cannot accidentally turn this into a different test.
    host('source', 'mkdir', '-p', '/tmp/awg', '/tmp/wg')
    awg = (SOURCE/'awg/Dockerfile').read_text()
    awg += '\nRUN sed -i \'/^add_if() {$/,/^}$/c\\add_if() {\\n\\tcmd amneziawg-go "$INTERFACE"\\n}\' /usr/bin/awg-quick\n'
    copy('source', awg, '/tmp/awg/Dockerfile')
    d('source', 'build', '--network', 'host', '-t', 'amnezia-awg2:test', '/tmp/awg')
    # WireGuard uses the host's ordinary kernel implementation.
    copy('source', (SOURCE/'wireguard/Dockerfile').read_text(), '/tmp/wg/Dockerfile')
    d('source', 'build', '--network', 'host', '-t', 'amnezia-wireguard:test', '/tmp/wg')
    d('source', 'network', 'create', '--subnet', '172.29.172.0/24', '--opt',
      'com.docker.network.bridge.name=amn0', 'amnezia-dns-net')
    clients = []
    for awg in (False, True):
        name, folder, tool, iface, port, subnet = ('amnezia-awg2', 'awg', 'awg', 'awg0', 51821, '10.88.0') if awg else (
            'amnezia-wireguard', 'wireguard', 'wg', 'wg0', 51820, '10.87.0')
        image = name+':test'
        key = lambda action, data=None: d('source', 'run', '--rm', '-i', '--entrypoint', tool, image, action, data=data).strip()
        sk, ck, psk = key('genkey'), key('genkey'), key('genpsk')
        sp, cp = key('pubkey', sk+'\n'), key('pubkey', ck+'\n')
        settings = 'Jc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 0\nS4 = 0\nH1 = 1001-1010\nH2 = 2001-2010\nH3 = 3001-3010\nH4 = 4001-4010\n' if awg else ''
        if awg and header_protection:
            settings = settings.replace('S3 = 0', 'S3 = 12').replace('S4 = 0', 'S4 = 12')
            settings += 'HeaderProtectionKey = '+key('genkey')+'\n'
        config = f'[Interface]\nPrivateKey = {sk}\nAddress = {subnet}.1/24\nListenPort = {port}\n{settings}\n[Peer]\nPublicKey = {cp}\nPresharedKey = {psk}\nAllowedIPs = {subnet}.2/32\n'
        state = '/tmp/state-'+folder
        host('source', 'mkdir', '-p', state+'/'+folder)
        copy('source', config, state+'/'+folder+'/'+iface+'.conf')
        copy('source', '[{"clientId":"migration-synthetic-existing"}]', state+'/'+folder+'/clientsTable')
        startup = (SOURCE/folder/'start.sh').read_text().replace('$AWG_SUBNET_IP', subnet+'.1').replace('$WIREGUARD_SUBNET_IP', subnet+'.1').replace('$WIREGUARD_SUBNET_CIDR', '24')
        copy('source', startup, state+'/start.sh', '755')
        d('source', 'create', '--name', name, '--privileged', '--restart', 'always', '--log-driver', 'none', '-p', f'{port}:{port}/udp', image)
        d('source', 'cp', state+'/.', name+':/opt/amnezia/')
        d('source', 'network', 'connect', 'amnezia-dns-net', name)
        d('source', 'start', name)
        ready(name, tool, iface)
        clients.append({'name': name, 'tool': tool, 'port': port, 'peer': cp, 'serverPublic': sp, 'settings': dict(line.split(' = ', 1) for line in settings.strip().splitlines()) if settings else {},
                        'config': f'[Interface]\nPrivateKey = {ck}\nAddress = {subnet}.2/32\n{settings}\n[Peer]\nPublicKey = {sp}\nPresharedKey = {psk}\nAllowedIPs = {subnet}.1/32,172.29.172.254/32\nEndpoint = ENDPOINT:{port}\nPersistentKeepalive = 1\n', 'ping': subnet+'.1'})
    # Standard DNS image/config, not a mocked resolver.
    d('source', 'build', '--network', 'host', '-t', 'amnezia-dns:test', '/src/client/server_scripts/dns')
    d('source', 'run', '-d', '--name', 'amnezia-dns', '--restart', 'always', '--network',
      'amnezia-dns-net', '--ip', '172.29.172.254', 'amnezia-dns:test')
    host('source', 'cp', '-r', '/src/client/server_scripts/connection_updates', '/tmp/delivery')
    info = json.loads(host('source', 'sh', '/tmp/delivery/install.sh', '/tmp/delivery', 'vpn.example.test'))
    # Synthetic signed token for the existing AWG client, retained byte for byte.
    issued = json.loads(d('source', 'run', '--rm', '-i', '--network', 'none', '--mount',
                          'type=volume,source=amnezia-connection-updates-state,target=/data',
                          'amnezia-connection-updates:1', 'issue', data=json.dumps({
                              'container': 'amnezia-awg2', 'clientPublicKey': clients[1]['peer'],
                              'settings': {'hostName': 'vpn.example.test', 'port': 51821, 'server_pub_key': clients[1]['serverPublic'], **clients[1]['settings']}})))
    return clients, info, issued


def traffic(clients, address):
    # Original profiles/keys/PSKs: only the resolved endpoint address changes.
    for c in clients:
        name = 'unchanged-'+c['tool']
        existing = d('source', 'ps', '-aq', '--filter', 'name=^/'+name+'$').strip()
        if existing:
            d('source', 'rm', '-f', existing)
        d('source', 'run', '-d', '--name', name, '--privileged', '--entrypoint', 'sh', c['name']+':test', '-c', 'tail -f /dev/null')
        copy('source', c['config'].replace('ENDPOINT', address), '/tmp/original.conf')
        d('source', 'cp', '/tmp/original.conf', name+':/tmp/original.conf')
        d('source', 'exec', name, c['tool']+'-quick', 'up', '/tmp/original.conf')
        for _ in range(15):
            r = cmd('docker', 'exec', HOSTS['source'], 'docker', 'exec', name, 'ping', '-c', '1', '-W', '1', c['ping'], check=False)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Original client traffic failed: '+c['tool'])
        d('source', 'exec', name, 'nslookup', '-type=soa', '.', '172.29.172.254')


def fetch(info, issued, address):
    # Exercise the old bearer token and pin with real TLS over the published port.
    script = """import base64,http.client,json,socket,ssl,sys,subprocess,tempfile
r=json.load(sys.stdin); cert=base64.b64decode(r['info']['certificate']); context=ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(cert))
with socket.create_connection((r['address'],8443),timeout=10) as raw:
 with context.wrap_socket(raw,server_hostname=r['info']['host']) as tls:
  assert tls.getpeercert(binary_form=True)==cert
  tls.sendall(('GET /v1/connections/'+r['issued']['id']+' HTTP/1.1\\r\\nHost: '+r['info']['host']+'\\r\\nAuthorization: Bearer '+r['issued']['token']+'\\r\\nConnection: close\\r\\n\\r\\n').encode())
  response=http.client.HTTPResponse(tls); response.begin(); assert response.status==200; envelope=json.loads(response.read(65536))
with tempfile.TemporaryDirectory() as directory:
 from pathlib import Path
 root=Path(directory); (root/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+base64.b64decode(r['info']['publicKey'])); (root/'payload').write_bytes(base64.b64decode(envelope['payload'])); (root/'signature').write_bytes(base64.b64decode(envelope['signature']))
 subprocess.run(['openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(root/'key.der'),'-rawin','-in',str(root/'payload'),'-sigfile',str(root/'signature')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 print((root/'payload').read_text())
"""
    return json.loads(host('source', 'python3', '-c', script, data=json.dumps({'info': info, 'issued': issued, 'address': address})))


def main():
    setup()
    clients, info, issued = fixture()
    addresses = {s: cmd('docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', h).strip() for s, h in HOSTS.items()}
    traffic(clients, addresses['source'])
    before_feed = fetch(info, issued, addresses['source'])
    assert before_feed['revision'] == '1'
    snapshot = agent('source', 'export')
    # State copy uses a private local file in the app; test streams private bytes
    # across the fixture boundary without writing them to the public repo.
    bundle = host('source', 'cat', snapshot['file'], binary=True)
    assert len(bundle) == snapshot['bytes']
    host('target', 'mkdir', '-m', '700', '/tmp/amnezia-migration-'+OP)
    host('target', 'sh', '-ec', 'umask 077; cat > "$1"', 'sh', '/tmp/amnezia-migration-'+OP+'/incoming.tar', data=bundle, binary=True)
    agent('target', 'receive')
    agent('target', 'import', sha256=snapshot['sha256'])
    agent('source', 'source-check')
    probes = agent('target', 'probe-create', address=addresses['target'])
    agent('source', 'probe-run', configs=probes['configs'], address=addresses['target'])
    agent('target', 'probe-remove')
    agent('target', 'verify')
    agent('target', 'probe-confirm')
    # Corrupt source and ensure cutover refuses it, then restore exact state.
    d('source', 'exec', 'amnezia-awg2', 'sh', '-c', 'echo changed >> /opt/amnezia/awg/clientsTable')
    assert agent('source', 'source-check', expect=False)['reason'] == 'source_changed'
    d('source', 'exec', 'amnezia-awg2', 'sh', '-c', "printf '%s' '[{\"clientId\":\"migration-synthetic-existing\"}]' > /opt/amnezia/awg/clientsTable")
    agent('source', 'source-stop')
    # A lost SSH reply at cutover is recovered from durable intent and immutable IDs.
    assert agent('source', 'status')['phase'] == 'stopped'
    assert not any(agent('source', 'status')['running'].values())
    assert agent('target', 'status')['phase'] == 'ready'
    agent('source', 'source-stop')  # Safe retry after an unknown response.
    agent('target', 'activate')
    traffic(clients, addresses['target'])
    assert json.loads(d('target', 'exec', 'amnezia-connection-updates', '/updates', 'info'))['publicKey'] == info['publicKey']
    after_feed = fetch(info, issued, addresses['target'])
    assert after_feed['revision'] == before_feed['revision'] and after_feed['settings'] == before_feed['settings']
    # Advance the signed feed on target; rollback must preserve the new replay floor.
    d('target', 'run', '--rm', '-i', '--network', 'none', '--mount',
      'type=volume,source=amnezia-connection-updates-state,target=/data',
      json.loads(d('target', 'inspect', 'amnezia-connection-updates'))[0]['Image'], 'publish',
      data=json.dumps({'container': 'amnezia-awg2', 'settings': after_feed['settings']}))
    assert fetch(info, issued, addresses['target'])['revision'] == '2'
    latest = agent('target', 'rollback-export')
    store = host('target', 'cat', latest['file'], binary=True)
    host('source', 'mkdir', '-p', '/tmp/amnezia-migration-'+OP)
    host('source', 'sh', '-ec', 'umask 077; cat > "$1"', 'sh', '/tmp/amnezia-migration-'+OP+'/rollback.tar', data=store, binary=True)
    agent('source', 'rollback-import', sha256=latest['sha256'])
    # A stale snapshot cannot overwrite a newer replay floor, even on a retry.
    stale = host('source', 'cat', '/var/lib/amnezia/migrations/'+OP+'/volume.tar', binary=True)
    import hashlib
    host('source', 'sh', '-ec', 'umask 077; cat > "$1"', 'sh', '/tmp/amnezia-migration-'+OP+'/rollback.tar', data=stale, binary=True)
    assert agent('source', 'rollback-import', expect=False, sha256=hashlib.sha256(stale).hexdigest())['reason'] == 'rollback_would_lower_revision'
    agent('source', 'abort')
    traffic(clients, addresses['source'])
    assert fetch(info, issued, addresses['source'])['revision'] == '2'
    agent('source', 'finalize')
    agent('target', 'finalize')
    agent('source', 'finalize')  # Cleanup retries are idempotent after SSH loss.
    for side in HOSTS:
        assert agent(side, 'status')['phase'] == 'finalized'
        assert host(side, 'sh', '-c', 'test ! -f /var/lib/amnezia/migrations/'+OP+'/bundle.tar; test ! -f /var/lib/amnezia/migrations/'+OP+'/volume.tar') == ''
    print('PASS: WG + AWG unchanged clients, external UDP probes, DNS, old signed token + TLS pin, drift rejection, switch and rollback retaining revision 2')


if __name__ == '__main__':
    try:
        main()
    finally:
        for name in HOSTS.values():
            cmd('docker', 'rm', '-f', name, check=False)
        cmd('docker', 'network', 'rm', NETWORK, check=False)
