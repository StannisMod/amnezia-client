#!/usr/bin/env python3
"""Real IPsec replacement; fixed names require a disposable Docker daemon."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from test_ipsec_restart import run


def prepare_peer(container, base_image):
    """Independent client and echo origin, entirely inside the private daemon."""
    gateway = json.loads(run('docker', 'network', 'inspect', 'bridge'))[0]['IPAM']['Config'][0]['Gateway']
    run('docker', 'exec', container, 'bash', '-ec', '''
head -c 1024 /dev/urandom > /tmp/fixture-noise
certutil -S -c 'IKEv2 VPN CA' -n fixture-client -s 'CN=Fixture Client' -m 33 -t ',,' \
 --keyUsage digitalSignature,keyEncipherment --extKeyUsage clientAuth --extSAN dns:fixture-client \
 -k rsa -g 2048 -v 1 -d sql:/etc/ipsec.d -z /tmp/fixture-noise
pk12util -o /tmp/client.p12 -n fixture-client -d sql:/etc/ipsec.d -W fixture-password -K ''
openssl pkcs12 -in /tmp/client.p12 -passin pass:fixture-password -nodes -nocerts -out /tmp/client.pem
''')
    with tempfile.TemporaryDirectory() as directory:
        files = Path(directory)
        # Reuse the already loaded immutable Alpine/Libreswan baseline instead
        # of fetching the product Dockerfile's unrelated upstream base again.
        # The separate peer runs strongSwan, never the server's Libreswan daemon.
        assert re.fullmatch(r'amneziavpn/ipsec-server@sha256:[0-9a-f]{64}', base_image)
        run('docker', 'image', 'inspect', base_image)
        (files / 'Dockerfile').write_text('FROM ' + base_image + '\nRUN apk add --no-cache strongswan python3\nENTRYPOINT ["tail", "-f", "/dev/null"]\n')
        run('docker', 'build', '-t', 'ipsec-update-peer:local', str(files), timeout=180)
        client = run('docker', 'run', '-d', '--privileged', '--name', 'ipsec-update-peer', 'ipsec-update-peer:local')
        run('docker', 'exec', client, 'mkdir', '-p', '/etc/swanctl/x509ca', '/etc/swanctl/x509', '/etc/swanctl/private')
        for nickname, target in (('IKEv2 VPN CA', '/etc/swanctl/x509ca/ca.pem'), ('fixture-client', '/etc/swanctl/x509/client.pem')):
            (files / 'cert').write_text(run('docker', 'exec', container, 'certutil', '-L', '-d', 'sql:/etc/ipsec.d', '-n', nickname, '-a') + '\n')
            run('docker', 'cp', str(files / 'cert'), client + ':' + target)
        run('docker', 'cp', container + ':/tmp/client.pem', str(files / 'key'))
        run('docker', 'cp', str(files / 'key'), client + ':/etc/swanctl/private/client.pem')
        (files / 'swanctl.conf').write_text('''connections {
 fixture {
  version = 2
  remote_addrs = ''' + gateway + '''
  vips = 0.0.0.0, ::
  proposals = aes256-sha256-modp2048
  local {
   auth = pubkey
   certs = client.pem
   id = fixture-client
  }
  remote {
   auth = pubkey
   id = 198.51.100.1
  }
  children {
   tunnel {
    remote_ts = 0.0.0.0/0, ::/0
    esp_proposals = aes128gcm16
   }
  }
 }
}
''')
        run('docker', 'cp', str(files / 'swanctl.conf'), client + ':/etc/swanctl/swanctl.conf')
    run('docker', 'exec', client, 'sh', '-ec', '''
printf 'charon { rsa_pss = yes\n }\n' > /etc/strongswan.d/fixture.conf
printf 'bypass-lan { load = no\n }\n' > /etc/strongswan.d/charon/bypass-lan.conf
printf 'resolve { load = no\n }\n' > /etc/strongswan.d/charon/resolve.conf
for protocol in tcp udp; do
 iptables -A OUTPUT -p "$protocol" --dport 18081 -m policy --dir out --pol none -j REJECT
done
''')
    run('docker', 'exec', '-d', client, '/usr/lib/strongswan/charon')
    for _ in range(50):
        check = subprocess.run(['docker', 'exec', client, 'test', '-S', '/run/charon.vici'], capture_output=True)
        if check.returncode == 0:
            break
        time.sleep(.1)
    run('docker', 'exec', client, 'swanctl', '--load-all')
    echo = '''import socket,threading
def tcp(s):
 while True:
  c,a=s.accept()
  with c:c.sendall(c.recv(64))
def udp(s):
 while True:
  b,a=s.recvfrom(64);s.sendto(b,a)
for kind,handler in ((socket.SOCK_STREAM,tcp),(socket.SOCK_DGRAM,udp)):
 s=socket.socket(socket.AF_INET,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',18081))
 if kind==socket.SOCK_STREAM:s.listen()
 threading.Thread(target=handler,args=(s,),daemon=True).start()
threading.Event().wait()
'''
    origin = subprocess.Popen(['python3', '-u', '-c', echo])

    def probe(label):
        # Explicitly negotiate again using the exact same stored client files.
        subprocess.run(['docker', 'exec', client, 'swanctl', '--terminate', '--ike', 'fixture'], capture_output=True, timeout=10)
        run('docker', 'exec', client, 'swanctl', '--initiate', '--child', 'tunnel', '--timeout', '15')
        run('docker', 'exec', client, 'python3', '-c', '''import socket,sys
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
 with socket.socket(socket.AF_INET,kind) as s:
  s.settimeout(3);s.connect((sys.argv[1],18081));s.sendall(b'unchanged-key');assert s.recv(64)==b'unchanged-key'
''', gateway)
        status = run('docker', 'exec', client, 'swanctl', '--list-sas')
        assert 'INSTALLED' in status and '192.168.43.' in status, status
        print('PASS: unchanged independent IKEv2 client TCP/UDP ' + label, flush=True)

    return probe, origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qt-update-test', type=Path,
                        help='test_server_edit binary: execute the successful update through production C++ SSH')
    args = parser.parse_args()
    labels = json.loads(run('docker', 'info', '--format', '{{json .Labels}}'))
    assert 'amnezia.test-environment=disposable' in labels, 'requires private disposable daemon'
    assert not run('docker', 'ps', '-aq'), 'requires empty disposable daemon'
    source = Path(__file__).resolve().parents[3] / 'client/server_scripts'
    old_image = 'amneziavpn/ipsec-server@sha256:080673496751055c76389c76d87329f033ad7b514f52a776651617ba14179540'
    container = run('docker', 'run', '-d', '--privileged', '--restart=always',
                    '-p', '500:500/udp', '-p', '4500:4500/udp', '--name', 'amnezia-ipsec', old_image)
    configuration = (source / 'ipsec/configure_container.sh').read_text()
    initialize = re.search(r'amnezia_ipsec_initialize_nss\(\) \{.*?^\}', configuration, re.MULTILINE | re.DOTALL).group(0)
    factory = configuration.split('if [ "$IPSEC_VPN_DISABLE_IKEV2" != "yes" ]; then\n', 1)[1].split('cat > /etc/ipsec.d/ikev2.conf <<EOF', 1)[0]
    run('docker', 'exec', '-i', container, 'bash', '-se', input=(
        'export SERVER_IP_ADDRESS=198.51.100.1\n' + initialize + '\namnezia_ipsec_initialize_nss\n' + factory))
    body = configuration.split('cat > /etc/ipsec.d/ikev2.conf <<EOF\n', 1)[1].split('\nEOF', 1)[0]
    for variable, value in {'SERVER_IP_ADDRESS': '198.51.100.1', 'PRIMARY_SERVER_DNS': '1.1.1.1',
                            'SECONDARY_SERVER_DNS': '8.8.8.8', 'IPSEC_IKEV2_SUBNETS': '0.0.0.0/0',
                            'IPSEC_IKEV2_POOL': '192.168.43.10-192.168.43.250'}.items():
        body = body.replace('$' + variable, value)
    # Use the shipping shared/IKEv1 stanzas too: replacing an IKEv2-only toy
    # configuration would miss Libreswan 5's changed default IKEv1 policy.
    main_config = configuration.split('cat > /etc/ipsec.conf <<EOF\n', 1)[1].split('\nEOF', 1)[0]
    main_config = main_config.replace('  ikev1-policy=accept\n', '')
    main_config += '\n' + configuration.split("cat >> /etc/ipsec.conf <<'EOF'\n", 1)[1].split('\nEOF', 1)[0]
    main_config += '\n' + configuration.split('cat >> /etc/ipsec.conf <<EOF\n', 1)[1].split('\nEOF', 1)[0]
    main_config += '\ninclude /etc/ipsec.d/*.conf\n'
    for variable, value in {'SERVER_IP_ADDRESS': '198.51.100.1', 'IPSEC_VPN_L2TP_NET': '192.168.42.0/24',
                            'IPSEC_VPN_XAUTH_NET': '192.168.43.0/24', 'IPSEC_VPN_XAUTH_POOL': '192.168.43.10-192.168.43.250',
                            'IPSEC_VPN_SHA2_TRUNCBUG': 'no', 'PRIMARY_DNS': '1.1.1.1', 'SECONDARY_DNS': '8.8.8.8'}.items():
        main_config = main_config.replace('$' + variable, value)
    with tempfile.TemporaryDirectory() as directory:
        files = Path(directory)
        for name, content, target in (
            ('main', main_config, '/etc/ipsec.conf'),
            ('ikev2', body + '\n', '/etc/ipsec.d/ikev2.conf'),
            ('secrets', '# fixture: preserve verbatim\n', '/etc/ipsec.secrets')):
            (files / name).write_text(content)
            run('docker', 'cp', str(files / name), container + ':' + target)
    run('docker', 'exec', container, 'sh', '-ec',
        'mkdir -p /etc/ppp /etc/xl2tpd /opt/amnezia; rm -f /etc/xl2tpd/xl2tpd.conf; '
        'iptables -t nat -A POSTROUTING -s 192.168.43.0/24 -o eth0 -m policy --dir out --pol none -j MASQUERADE; '
        'ipsec pluto --config /etc/ipsec.conf; ipsec addconn --autoall --config /etc/ipsec.conf')
    for _ in range(30):
        if '"ikev2-cp"' in run('docker', 'exec', container, 'ipsec', 'auto', '--status'):
            break
        time.sleep(.2)
    else:
        raise AssertionError('old backend did not load')
    for connection in ('l2tp-psk', 'xauth-psk'):
        assert '"' + connection + '"' in run('docker', 'exec', container, 'ipsec', 'auto', '--status')
    probe, origin = prepare_peer(container, old_image)
    import atexit
    atexit.register(origin.terminate)
    probe('before update')
    stage = Path('/tmp/amnezia-update-' + uuid.uuid4().hex)
    stage.mkdir()
    (stage / 'Dockerfile').write_text((source / 'ipsec/Dockerfile').read_text())
    (stage / 'enable_ipv6.sh').write_text((source / 'ipsec/enable_ipv6.sh').read_text())
    (stage / 'network.sh').write_text((source / 'prepare_ipv6_network.sh').read_text())
    (stage / 'start.sh').write_text('#!/bin/bash\n' + (stage / 'enable_ipv6.sh').read_text() + '\n' +
                                   (source / 'ipsec/start.sh').read_text().split('\n', 1)[1])
    # Fail only after cutover, so rollback must restart the original inert image
    # and its daemon rather than merely leave a still-running backend alone.
    failed_stage = Path('/tmp/amnezia-update-' + uuid.uuid4().hex)
    failed_stage.mkdir()
    for filename in ('Dockerfile', 'enable_ipv6.sh', 'network.sh'):
        (failed_stage / filename).write_text((stage / filename).read_text())
    (failed_stage / 'start.sh').write_text('#!/bin/sh\n# amnezia-managed-ipsec-startup-v1\nexit 1\n')
    failed = subprocess.run(['sh', str(source / 'update_ipsec.sh'), 'ipsec', str(failed_stage)],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    print(failed.stdout, flush=True)
    assert failed.returncode != 0 and 'amnezia_update=rolled_back' in failed.stdout
    assert run('docker', 'inspect', '-f', '{{.Id}}', 'amnezia-ipsec') == container
    assert run('docker', 'inspect', '-f', '{{.State.Running}}', container) == 'true'
    assert '"ikev2-cp"' in run('docker', 'exec', container, 'ipsec', 'auto', '--status')
    assert run('docker', 'exec', container, 'cat', '/etc/ipsec.d/ikev2.conf') == body
    run('docker', 'exec', container, 'iptables', '-t', 'nat', '-C', 'POSTROUTING',
        '-s', '192.168.43.0/24', '-o', 'eth0', '-m', 'policy', '--dir', 'out', '--pol', 'none', '-j', 'MASQUERADE')
    print('PASS: failed candidate restores original old image, daemon and unchanged IPv4 configuration', flush=True)
    probe('after rollback')
    if args.qt_update_test:
        from ipsec_ssh_client import update_with_qt
        update_with_qt(args.qt_update_test)
    else:
        result = subprocess.run(['sh', str(source / 'update_ipsec.sh'), 'ipsec', str(stage)],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        print(result.stdout, flush=True)
        work = Path('/var/lib/amnezia/updates/amnezia-ipsec-' + stage.name.removeprefix('amnezia-update-'))
        if result.returncode or 'amnezia_update=ok' not in result.stdout:
            print((work / 'update.log').read_text(), flush=True)
            raise AssertionError('replacement failed')
    assert run('docker', 'inspect', '-f', '{{.Id}}', 'amnezia-ipsec') != container
    assert run('docker', 'inspect', '-f', '{{.State.Running}}', container) == 'false'
    assert run('docker', 'exec', 'amnezia-ipsec', 'cat', '/etc/ipsec.secrets') == '# fixture: preserve verbatim'
    run('docker', 'exec', 'amnezia-ipsec', 'iptables', '-t', 'nat', '-C', 'POSTROUTING',
        '-s', '192.168.43.0/24', '-o', 'eth0', '-m', 'policy', '--dir', 'out', '--pol', 'none', '-j', 'MASQUERADE')
    probe('after replacement and restart')
    status = run('docker', 'exec', 'amnezia-ipsec', 'ipsec', 'auto', '--status')
    for connection in ('l2tp-psk', 'xauth-psk'):
        assert '"' + connection + '"' in status, status
    print('PASS: actual old/new replacement, restart, preserved NSS identities and secrets', flush=True)


if __name__ == '__main__':
    main()
