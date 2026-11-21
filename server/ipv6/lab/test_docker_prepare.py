#!/usr/bin/env python3
"""Run the production IPv6 bridge preparer against disposable nested Docker.

This proves bridge installation, ownership, idempotence and live attachment
with retained IPv4 TCP and DNS, not Internet IPv6 reachability. All routes and networks created here belong to the private daemon.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import time
import tempfile
import uuid
from test_restart import test_restarts


def command(*args, check=True, data=None, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=data)
    if check and result.returncode:
        raise RuntimeError(f'{args!r}: {result.stdout}{result.stderr}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='amnezia-local-vpn-tests')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    image = command('docker', 'image', 'inspect', '-f', '{{.Id}}', args.image).stdout.strip()
    fixture = 'amnezia-ipv6-prepare-' + uuid.uuid4().hex[:12]
    def inside(*parts, **kwargs):
        prefix = ('docker', 'exec', '-i', fixture) if kwargs.get('data') is not None else ('docker', 'exec', fixture)
        return command(*prefix, *parts, **kwargs)
    def network(name):
        return json.loads(inside('docker', 'network', 'inspect', name).stdout)[0]
    def prepare(check=True):
        return inside('sh', '/prepare_ipv6_network.sh', check=check)
    try:
        command('docker', 'run', '-d', '--network', 'none', '--privileged',
                '--name', fixture, '--label', 'amnezia.test-environment=disposable',
                '-e', 'DOCKER_TLS_CERTDIR=', image, '--host=unix:///var/run/docker.sock',
                '--feature', 'containerd-snapshotter=true')
        assert command('docker', 'inspect', '-f', '{{.HostConfig.NetworkMode}}', fixture).stdout.strip() == 'none'
        deadline = time.monotonic() + 45
        while inside('docker', 'info', check=False).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError('private Docker daemon did not start')
            time.sleep(0.2)
        command('docker', 'cp', str(root/'client/server_scripts/prepare_ipv6_network.sh'),
                fixture + ':/prepare_ipv6_network.sh')
        inside('docker', 'network', 'create', '--label', 'fixture=dns-preserved', 'amnezia-dns-net')
        dns_before = network('amnezia-dns-net')
        absent = prepare()
        assert 'no-host-default-route' in absent.stdout
        assert inside('docker', 'network', 'inspect', 'amnezia-ipv6-egress', check=False).returncode != 0
        inside('sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0', 'net.ipv6.conf.default.disable_ipv6=0')
        inside('ip', 'link', 'add', 'fixture-uplink', 'type', 'dummy')
        inside('ip', 'link', 'set', 'fixture-uplink', 'up')
        inside('ip', '-6', 'addr', 'add', 'fd98::2/64', 'dev', 'fixture-uplink')
        inside('ip', '-6', 'route', 'add', 'default', 'dev', 'fixture-uplink')
        installed = prepare()
        assert 'bridge-prepared-egress-unverified' in installed.stdout
        first = network('amnezia-ipv6-egress')
        assert first['Driver'] == 'bridge' and first['EnableIPv6'] and not first['EnableIPv4']
        assert first['Labels']['com.amnezia.ipv6-egress'] == 'v1'
        subnets = [ipaddress.ip_network(row['Subnet']) for row in first['IPAM']['Config']]
        assert subnets and all(s.version == 6 and s.prefixlen == 64 for s in subnets)
        assert first['Options']['com.docker.network.bridge.name'] == 'amn6'
        assert 'amn6' in inside('ip', 'link', 'show', 'amn6').stdout
        prepare()
        assert network('amnezia-ipv6-egress') == first, 'repeat preparation changed the installed network'
        assert network('amnezia-dns-net') == dns_before, 'preparation changed the pre-existing DNS bridge'
        # Load an image into this private daemon; never borrow the host socket.
        with tempfile.TemporaryDirectory(prefix='amnezia-ipv6-image-') as transfer:
            archive = Path(transfer) / 'image.tar'
            command('docker', 'save', '--output', str(archive), args.image)
            command('docker', 'cp', str(archive), fixture + ':/fixture-image.tar')
            inside('docker', 'load', '--input', '/fixture-image.tar')
            inside('rm', '/fixture-image.tar')
        echo = """import socketserver
from pathlib import Path
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(4096)
   if not data: break
   self.request.sendall(data)
server=socketserver.ThreadingTCPServer(('0.0.0.0',29182),Echo)
Path('/ready').touch()
server.serve_forever()
"""
        inside('docker', 'run', '-d', '--pull=never', '--name', 'fixture-peer',
               '--network', 'amnezia-dns-net', '--entrypoint', 'python3', args.image, '-c', echo)
        deadline = time.monotonic() + 15
        while inside('docker', 'exec', 'fixture-peer', 'test', '-f', '/ready', check=False).returncode:
            if time.monotonic() >= deadline:
                logs = inside('docker', 'logs', 'fixture-peer')
                raise RuntimeError('TCP echo server not ready: ' + logs.stdout + logs.stderr)
            time.sleep(0.05)
        client = """import json,socket,time
from pathlib import Path
peer=socket.gethostbyname('fixture-peer')
s=socket.create_connection((peer,29182),timeout=10)
def check(payload):
 s.sendall(payload)
 received=b''
 while len(received)<len(payload):
  part=s.recv(len(payload)-len(received))
  assert part
  received+=part
 assert received==payload
check(b'before-network-attachment')
identity=(s.getsockname(),s.getpeername())
Path('/ready').touch()
while not Path('/continue').exists(): time.sleep(0.02)
assert socket.gethostbyname('fixture-peer')==peer
check(b'original-tcp-after-network-attachment')
assert identity==(s.getsockname(),s.getpeername())
Path('/result').write_text(json.dumps({'tcp_preserved':True,'dns_preserved':True}))
time.sleep(300)
"""
        for container in ('amnezia-wireguard', 'amnezia-awg2'):
            inside('docker', 'run', '-d', '--pull=never', '--name', container,
                   '--network', 'amnezia-dns-net', '--entrypoint', 'python3', args.image, '-c', client)
            deadline = time.monotonic() + 15
            while inside('docker', 'exec', container, 'test', '-f', '/ready', check=False).returncode:
                if time.monotonic() >= deadline:
                    logs = inside('docker', 'logs', container)
                    raise RuntimeError('TCP client did not become ready: ' + logs.stdout + logs.stderr)
                time.sleep(0.05)
            baseline = json.loads(inside('docker', 'inspect', container).stdout)[0]
            routes = inside('docker', 'exec', container, 'ip', '-4', 'route', 'show', 'table', 'all').stdout
            resolver = inside('docker', 'exec', container, 'cat', '/etc/resolv.conf').stdout
            attached = inside('sh', '-c', '. /prepare_ipv6_network.sh; amnezia_attach_ipv6_network "$1"', 'sh', container)
            assert 'attached-egress-unverified' in attached.stdout
            current = json.loads(inside('docker', 'inspect', container).stdout)[0]
            ipv6_endpoint = current['NetworkSettings']['Networks']['amnezia-ipv6-egress']
            assert ipv6_endpoint['NetworkID'] == first['Id'] and ipv6_endpoint['GlobalIPv6Address']
            members = network('amnezia-ipv6-egress')['Containers']
            assert current['Id'] in members and members[current['Id']]['Name'] == container
            assert current['NetworkSettings']['Networks']['amnezia-dns-net'] == baseline['NetworkSettings']['Networks']['amnezia-dns-net']
            assert inside('docker', 'exec', container, 'ip', '-4', 'route', 'show', 'table', 'all').stdout == routes
            assert inside('docker', 'exec', container, 'cat', '/etc/resolv.conf').stdout == resolver
            inside('sh', '-c', '. /prepare_ipv6_network.sh; amnezia_attach_ipv6_network "$1"', 'sh', container)
            assert json.loads(inside('docker', 'inspect', container).stdout)[0]['NetworkSettings']['Networks'] == current['NetworkSettings']['Networks'], 'repeat attach changed endpoints'
            inside('docker', 'exec', container, 'touch', '/continue')
            deadline = time.monotonic() + 15
            while inside('docker', 'exec', container, 'test', '-f', '/result', check=False).returncode:
                if time.monotonic() >= deadline:
                    logs = inside('docker', 'logs', container)
                    raise RuntimeError('original TCP did not survive attachment: ' + logs.stdout + logs.stderr)
                time.sleep(0.05)
            assert json.loads(inside('docker', 'exec', container, 'cat', '/result').stdout) == dict(tcp_preserved=True,dns_preserved=True)
            inside('docker', 'rm', '-f', container)
        inside('docker', 'rm', '-f', 'fixture-peer')
        restart_results = test_restarts(inside, args.image, root)
        inside('docker', 'network', 'rm', 'amnezia-ipv6-egress')
        inside('docker', 'network', 'create', '--label', 'fixture=foreign', 'amnezia-ipv6-egress')
        foreign = network('amnezia-ipv6-egress')
        rejected = prepare(check=False)
        assert rejected.returncode != 0 and 'existing-network-conflict' in rejected.stderr
        assert network('amnezia-ipv6-egress') == foreign, 'foreign network was modified'
        assert network('amnezia-dns-net') == dns_before, 'conflict changed DNS bridge'
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'schema_version': 1, 'result': 'PASS', 'real_restarts': restart_results,
            'scope': 'production-script/private-docker-bridge-live-attachment-and-native-restarts', 'internet_egress': 'NOT_TESTED',
            'checks': ['no-route-no-network', 'actual-ipv6-only-bridge', 'idempotent-repeat',
                       'dns-bridge-preserved', 'foreign-network-rejected',
                       'live-attach-ipv4-routes-resolver-and-endpoint-preserved',
                       'original-ipv4-tcp-and-dns-survive-attach', 'repeat-attach-idempotent', 'actual-quick-native-tun-container-restarts',
                       'encrypted-ipv4-ipv6-tcp-after-restart', 'ipv4-boot-without-ipv6-egress']}, indent=2) + '\n')
        print('PASS: IPv6 bridge attachment, original IPv4 TCP/DNS and actual WG/AWG encrypted restart acceptance', flush=True)
    finally:
        command('docker', 'rm', '-f', '-v', fixture, check=False)


if __name__ == '__main__':
    main()
