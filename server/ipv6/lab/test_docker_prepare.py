#!/usr/bin/env python3
"""Run the production IPv6 bridge preparer against disposable nested Docker.

This proves bridge installation, ownership and idempotence, not Internet IPv6
reachability. All routes and networks created here belong to the private daemon.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import time
import uuid


def command(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
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
        return command('docker', 'exec', fixture, *parts, **kwargs)
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
        inside('docker', 'network', 'rm', 'amnezia-ipv6-egress')
        inside('docker', 'network', 'create', '--label', 'fixture=foreign', 'amnezia-ipv6-egress')
        foreign = network('amnezia-ipv6-egress')
        rejected = prepare(check=False)
        assert rejected.returncode != 0 and 'existing-network-conflict' in rejected.stderr
        assert network('amnezia-ipv6-egress') == foreign, 'foreign network was modified'
        assert network('amnezia-dns-net') == dns_before, 'conflict changed DNS bridge'
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'schema_version': 1, 'result': 'PASS',
            'scope': 'production-script/private-docker-bridge', 'internet_egress': 'NOT_TESTED',
            'checks': ['no-route-no-network', 'actual-ipv6-only-bridge', 'idempotent-repeat',
                       'dns-bridge-preserved', 'foreign-network-rejected']}, indent=2) + '\n')
        print('PASS: production IPv6 bridge installation, idempotence and ownership', flush=True)
    finally:
        command('docker', 'rm', '-f', '-v', fixture, check=False)


if __name__ == '__main__':
    main()
