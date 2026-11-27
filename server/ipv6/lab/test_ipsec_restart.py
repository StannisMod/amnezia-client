#!/usr/bin/env python3
"""Exercise real Docker restart, using only an owned network-none container."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=kwargs.pop('timeout', 40), **kwargs)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[3] / 'client/server_scripts/ipsec'
    configuration = (source / 'configure_container.sh').read_text()
    helper = (source / 'enable_ipv6.sh').read_text()
    image = run('docker', 'image', 'inspect', '--format', '{{.Id}}', args.image)
    container = run('docker', 'create', '--pull=never', '--network', 'none', '--privileged',
                    '--pids-limit', '128', '--memory', '256m', '--name', 'ipsec-restart-' + uuid.uuid4().hex[:12], image)
    try:
        run('docker', 'start', container)
        # Recreate an entirely local underlay at each boot; no Docker bridge,
        # published host port, public network or host interface is involved.
        underlay = '''
if ! ip link show fixture0 >/dev/null 2>&1; then
    ip link add fixture0 type dummy
    ip addr add 198.51.100.1/24 dev fixture0
    ip link set fixture0 up
    ip route add default dev fixture0
fi
'''
        run('docker', 'exec', '-i', container, 'bash', '-se', input=underlay)
        registry = (source.parents[1] / 'core/utils/selfhosted/scriptsRegistry.cpp').read_text()
        values = dict(re.findall(r'\{ "(\$IPSEC_VPN_[A-Z0-9_]+)", "([^"]+)" \}', registry))
        values.update({'$SERVER_IP_ADDRESS': '198.51.100.1', '$PRIMARY_SERVER_DNS': '1.1.1.1',
                       '$SECONDARY_SERVER_DNS': '8.8.8.8'})
        rendered = configuration
        for variable, value in values.items():
            rendered = rendered.replace(variable, value)
        run('docker', 'exec', '-i', container, 'bash', '-se', input=helper + '\n' + rendered)
        run('docker', 'exec', container, 'test', '-s', '/opt/amnezia/ipsec-ipv4.rules')
        run('docker', 'exec', container, 'test', '-s', '/opt/amnezia/ipsec-ipv4.sysctl')
        run('docker', 'exec', container, 'ipsec', 'whack', '--shutdown')
        run('docker', 'exec', container, 'sh', '-ec', 'while pidof pluto >/dev/null; do sleep .1; done')
        body = configuration.split('cat > /etc/ipsec.d/ikev2.conf <<EOF\n', 1)[1].split('\nEOF', 1)[0]
        for variable, value in {'SERVER_IP_ADDRESS': '198.51.100.1', 'PRIMARY_SERVER_DNS': '1.1.1.1',
                                'SECONDARY_SERVER_DNS': '8.8.8.8', 'IPSEC_IKEV2_SUBNETS': '0.0.0.0/0',
                                'IPSEC_IKEV2_POOL': '192.168.43.10-192.168.43.250'}.items():
            body = body.replace('$' + variable, value)
        body = body.replace('left=%defaultroute', 'left=198.51.100.1')
        with tempfile.TemporaryDirectory(prefix='ipsec-restart-files-') as directory:
            stage = Path(directory)
            files = {
                'start.sh': '#!/bin/bash\nset -x\n' + helper + '\n' + underlay + (source / 'start.sh').read_text().split('\n', 1)[1],
                'ipsec.conf': 'version 2.0\nconfig setup\n  uniqueids=no\ninclude /etc/ipsec.d/ikev2.conf\n',
                'ikev2.conf': body + '\n',
            }
            for name, contents in files.items():
                (stage / name).write_text(contents)
            for name, target in (('start.sh', '/opt/amnezia/start.sh'), ('ipsec.conf', '/etc/ipsec.conf'),
                                 ('ikev2.conf', '/etc/ipsec.d/ikev2.conf')):
                run('docker', 'cp', str(stage / name), container + ':' + target)
        run('docker', 'exec', container, 'chmod', '755', '/opt/amnezia/start.sh')
        run('docker', 'exec', '-d', container, '/opt/amnezia/start.sh')

        def logs():
            return subprocess.run(['docker', 'logs', container], text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=5).stdout

        def ready():
            deadline = time.monotonic() + 15
            while True:
                if run('docker', 'inspect', '--format', '{{.State.Running}}', container) != 'true':
                    raise RuntimeError('container exited: ' + logs())
                probe = subprocess.run(['docker', 'exec', container, 'sh', '-ec', 'pidof pluto && ipsec auto --status'],
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                if probe.returncode == 0 and 'ikev2-cp' in probe.stdout:
                    return
                if time.monotonic() >= deadline:
                    raise RuntimeError('IPsec did not start: ' + logs() + probe.stderr)
                time.sleep(.2)

        def identities():
            values = {}
            for nickname in ('IKEv2 VPN CA', '198.51.100.1'):
                cert = run('docker', 'exec', container, 'certutil', '-L', '-d', 'sql:/etc/ipsec.d', '-n', nickname, '-a')
                values[nickname + '/cert'] = hashlib.sha256(cert.encode()).hexdigest()
                key = run('docker', 'exec', container, 'bash', '-e', '-o', 'pipefail', '-c', '''
pk12util -o /tmp/restart-identity.p12 -n "$1" -d sql:/etc/ipsec.d -W fixture-password -K '' >/dev/null
openssl pkcs12 -legacy -in /tmp/restart-identity.p12 -passin pass:fixture-password -nodes -nocerts 2>/dev/null |
    openssl pkey -outform DER 2>/dev/null | sha256sum
''', 'sh', nickname)
                values[nickname + '/key'] = key.split()[0]
            return values

        ready()
        run('docker', 'exec', container, 'pidof', 'xl2tpd')
        def ipv4_nat():
            run('docker', 'exec', container, 'iptables', '-t', 'nat', '-C', 'POSTROUTING',
                '-s', '192.168.43.0/24', '-o', 'fixture0', '-m', 'policy', '--dir', 'out', '--pol', 'none', '-j', 'MASQUERADE')
            assert run('docker', 'exec', container, 'sysctl', '-n', 'net.ipv4.ip_forward') == '1'
        ipv4_nat()
        before = identities()
        stored = run('docker', 'exec', container, 'cat', '/etc/ipsec.d/ikev2.conf')
        run('docker', 'restart', '--time', '3', container)
        ready()
        run('docker', 'exec', container, 'pidof', 'xl2tpd')
        ipv4_nat()
        assert identities() == before, 'restart replaced a certificate or private key'
        assert run('docker', 'exec', container, 'cat', '/etc/ipsec.d/ikev2.conf') == stored
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({'status': 'PASS', 'image': image, 'identities': before,
            'fresh_configuration': True, 'ipv4_nat_and_forwarding': True, 'xl2tpd_running': True,
            'scope': 'full production configure and daemon/network policy after Docker restart; peer traffic is tested separately'}, indent=2) + '\n')
        print('PASS: full production configure and Docker restart restore IPsec, L2TP, IPv4 NAT/forwarding; identities unchanged')
    finally:
        subprocess.run(['docker', 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == '__main__':
    main()
