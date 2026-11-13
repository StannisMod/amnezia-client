#!/usr/bin/env python3
"""Run the application SSH/deployment path against an isolated Docker daemon.

The HTTPS origin uses the production probe's numeric IPv6 destinations, but is
entirely local, with a lab CA installed ONLY in disposable protocol containers.
This proves kernel egress, two NAT layers and authenticated TLS, not availability
of the public Internet. The Qt runner may use {fixture}, {pid}, {protocol} and
{expected} placeholders; no command is passed through a host shell.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid


def run(*args, data=None, check=True, timeout=180):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"fixture command failed: {args[:3]!r}: {result.stderr.decode(errors='replace')[-2000:]}")
    return result


HTTPS = r'''
import http.server,ssl,socket,os,json
class Server(http.server.HTTPServer): address_family=socket.AF_INET6
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  assert self.path in ('/dns-query?name=.&type=NS','/resolve?name=.&type=NS')
  with open('/run/provider-observations.jsonl','a') as f:
   f.write(json.dumps({'source':self.client_address[0],'host':self.headers.get('Host')})+'\n')
  data=b'{"Status":0,"Question":[{"name":".","type":2}],"Answer":[{"type":2,"data":"a.root-servers.net."}]}'
  self.send_response(200);self.send_header('Content-Type','application/dns-json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/lab.crt','/lab.key')
s=Server(('::',443),Handler);s.socket=context.wrap_socket(s.socket,server_side=True)
open('/run/provider.pid','w').write(str(os.getpid()));print('READY',flush=True);s.serve_forever()
'''

ECHO = r'''
import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('198.51.100.1',18081));s.listen()
def echo(c):
 with c:
  while True:
   data=c.recv(65536)
   if not data:return
   c.sendall(data)
print('READY',flush=True)
while True:
 c,a=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
'''

CLIENT = r'''
import socket,sys,json
s=socket.create_connection(('198.51.100.1',18081),timeout=15)
identity=s.getsockname();print(json.dumps({'ready':True,'port':identity[1]}),flush=True)
for line in sys.stdin:
 data=('retained:'+line.strip()).encode();s.sendall(data);answer=b''
 while len(answer)<len(data):
  part=s.recv(len(data)-len(answer));assert part;answer+=part
 assert answer==data and s.getsockname()==identity
 print('SAME_TCP',flush=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--tool-image', default='amnezia-local-vpn-tests')
    parser.add_argument('--builder-image', default='golang:1.27.1')
    parser.add_argument('--helper-image', default='amnezia-ipv6-upgrade-helper:local')
    parser.add_argument('runner', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    runner = args.runner[1:] if args.runner[:1] == ['--'] else args.runner
    if not runner:
        parser.error('provide the Qt test runner after --')
    root = Path(__file__).resolve().parents[3]
    fixture = 'amnezia-ipv6-activation-' + uuid.uuid4().hex[:12]
    children = []
    report = {'schema_version': 1, 'scope': 'isolated kernel/NAT/TLS/application SSH; not public Internet', 'protocols': {}}
    def inside(*parts, **kw):
        return run('docker', 'exec', '-i', fixture, *parts, **kw)
    def command(*parts):
        return inside(*parts).stdout.decode().strip()
    def pipe(*parts):
        process = subprocess.Popen(['docker', 'exec', '-i', fixture, *parts], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(process)
        return process
    def upload(data, path):
        inside('sh', '-ec', 'umask 077; cat > "$1"', 'sh', path, data=data)
    def serve_tls():
        process = pipe('ip', 'netns', 'exec', 'provider', 'python3', '-u', '/provider.py')
        assert process.stdout.readline().strip() == 'READY'
        return process
    try:
        for image in (args.tool_image, args.builder_image, args.helper_image):
            run('docker', 'image', 'inspect', image)
        run('docker', 'run', '-d', '--network', 'none', '--privileged', '--name', fixture,
            '--label', 'amnezia.test-environment=disposable', '-e', 'DOCKER_TLS_CERTDIR=', args.tool_image,
            '--host=unix:///var/run/docker.sock', '--feature', 'containerd-snapshotter=true',
            '--label', 'amnezia.test-environment=disposable')
        assert run('docker', 'inspect', '-f', '{{.HostConfig.NetworkMode}}', fixture).stdout.strip() == b'none'
        deadline = time.monotonic() + 60
        while inside('docker', 'info', check=False).returncode:
            if time.monotonic() > deadline:
                raise RuntimeError('private Docker daemon did not start')
            time.sleep(.2)
        # Preload ALL build inputs. The private daemon has no external route.
        save = subprocess.Popen(['docker', 'image', 'save', args.tool_image, args.builder_image, args.helper_image], stdout=subprocess.PIPE)
        children.append(save)
        load = subprocess.run(['docker', 'exec', '-i', fixture, 'docker', 'image', 'load'], stdin=save.stdout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        save.stdout.close()
        assert load.returncode == 0 and save.wait(timeout=30) == 0
        command('touch', '/run/amnezia-ipv6-fixture')
        command('sh', '-ec', 'mkdir -p /dev/net /run/sshd; test -c /dev/net/tun || mknod /dev/net/tun c 10 200')
        command('ssh-keygen', '-A')
        inside('chpasswd', data=b'root:synthetic-probe-fixture\n')
        command('/usr/sbin/sshd', '-p', '2222', '-o', 'PermitRootLogin=yes', '-o', 'PasswordAuthentication=yes')
        command('ip', 'netns', 'add', 'provider')
        command('ip', '-n', 'provider', 'link', 'set', 'lo', 'up')
        command('ip', 'link', 'add', 'uplink0', 'type', 'veth', 'peer', 'name', 'origin0', 'netns', 'provider')
        for namespace, iface, ipv4, ipv6 in ((None, 'uplink0', '198.51.100.2/24', '2001:db8:99::2/64'),
                                           ('provider', 'origin0', '198.51.100.1/24', '2001:db8:99::1/64')):
            prefix = ['ip'] if namespace is None else ['ip', '-n', namespace]
            command(*prefix, 'link', 'set', iface, 'up')
            command(*prefix, 'addr', 'add', ipv4, 'dev', iface)
            command(*prefix, '-6', 'addr', 'add', ipv6, 'dev', iface, 'nodad')
        command('ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:99::1', 'dev', 'uplink0')
        for address in ('2606:4700:4700::1111/128', '2001:4860:4860::8888/128'):
            command('ip', '-n', 'provider', '-6', 'addr', 'add', address, 'dev', 'lo', 'nodad')
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Isolated IPv6 provider',
                '-addext', 'subjectAltName=DNS:cloudflare-dns.com,DNS:dns.google',
                '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', '/lab.key', '-out', '/lab.crt')
        upload(HTTPS.encode(), '/provider.py')
        tls = serve_tls()
        echo = pipe('ip', 'netns', 'exec', 'provider', 'python3', '-u', '-c', ECHO)
        assert echo.stdout.readline().strip() == 'READY'
        command('docker', 'network', 'create', '--label', 'fixture=dns-preserved', 'amnezia-dns-net')
        command('docker', 'volume', 'create', '--label', 'org.amnezia.connection-updates=1', 'amnezia-connection-updates-state')
        # A real delivery service is used, including real signatures/state CAS.
        inside('docker', 'run', '--rm', '-i', '--network', 'none', '--mount', 'type=volume,source=amnezia-connection-updates-state,target=/data',
               args.helper_image, 'init', data=b'{"host":"127.0.0.1"}')
        command('docker', 'run', '-d', '--name', 'amnezia-connection-updates', '--network', 'none',
                '--mount', 'type=volume,source=amnezia-connection-updates-state,target=/data', args.helper_image)
        cert = inside('cat', '/lab.crt').stdout
        for protocol, tool, iface, subnet, kind in (('amnezia-wireguard', 'wg', 'wg0', '10.77.0', 'wireguard'),
                                                    ('amnezia-awg2', 'awg', 'awg0', '10.88.0', 'awg')):
            print('CHECK:', protocol, flush=True)
            command('docker', 'run', '-d', '--name', protocol, '--privileged', '--device', '/dev/net/tun',
                    '--entrypoint', 'sh', args.tool_image, '-c', 'exec sleep 1800')
            command('docker', 'network', 'connect', 'amnezia-dns-net', protocol)
            def vpn(*parts, **kw):
                return inside('docker', 'exec', '-i', protocol, *parts, **kw)
            native_key = inside('wg', 'genkey').stdout.strip()
            client_key = inside('wg', 'genkey').stdout.strip()
            client_public = inside('wg', 'pubkey', data=client_key+b'\n').stdout.strip().decode()
            offline_key = inside('wg', 'genkey').stdout.strip()
            offline_public = inside('wg', 'pubkey', data=offline_key+b'\n').stdout.strip().decode()
            extensions = 'Jc = 3\nJmin = 40\nJmax = 80\nS1 = 16\nS2 = 24\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\n' if tool == 'awg' else ''
            native = ('[Interface]\nPrivateKey = '+native_key.decode()+'\nListenPort = 51820\n'+extensions+
                      '[Peer]\nPublicKey = '+client_public+'\nAllowedIPs = '+subnet+'.2/32\n'+
                      '[Peer]\nPublicKey = '+offline_public+'\nAllowedIPs = '+subnet+'.3/32\n')
            vpn('sh', '-ec', 'umask 077; cat > /native.conf', data=native.encode())
            if tool == 'wg': vpn('ip', 'link', 'add', iface, 'type', 'wireguard')
            else: vpn('amneziawg-go', iface)
            vpn(tool, 'setconf', iface, '/native.conf')
            vpn('ip', 'addr', 'add', subnet+'.1/24', 'dev', iface)
            vpn('ip', 'link', 'set', iface, 'up')
            vpn('sysctl', '-w', 'net.ipv4.ip_forward=1')
            vpn('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', subnet+'.0/24', '!', '-o', iface, '-j', 'MASQUERADE')
            saved = vpn(tool, 'showconf', iface).stdout
            quick = saved.replace(b'[Interface]\n', ('[Interface]\nAddress = '+subnet+'.1/24\n').encode(), 1)
            path = '/opt/amnezia/'+kind+'/'+iface+'.conf'
            vpn('sh', '-ec', 'umask 077; mkdir -p "$1"; cat > "$2"', 'sh', '/opt/amnezia/'+kind, path, data=quick)
            startup = (root/'client/server_scripts'/kind/'start.sh').read_bytes()
            boot = ('\namnezia_enable_ipv6 '+iface+" || echo 'AMNEZIA_IPV6_FORWARDING_STATUS=boot-preparation-failed' >&2\n").encode()
            startup = startup.replace(boot, b'', 1)+b'\ntouch /run/forbidden-startup-body\n'
            vpn('sh', '-ec', 'umask 077; cat > /opt/amnezia/start.sh; chmod 700 /opt/amnezia/start.sh', data=startup)
            vpn('sh', '-ec', 'mkdir -p /etc/ssl/certs; cat > /etc/ssl/certs/ca-certificates.crt', data=cert)
            request = {'container': protocol, 'clientPublicKey': client_public,
                       'settings': {'hostName': '127.0.0.1', 'port': 51820,
                                    'server_pub_key': vpn(tool, 'show', iface, 'public-key').stdout.decode().strip()}}
            inside('docker', 'run', '--rm', '-i', '--network', 'none', '--mount', 'type=volume,source=amnezia-connection-updates-state,target=/data',
                   args.helper_image, 'issue', data=json.dumps(request).encode())
            client = protocol+'-client'
            command('docker', 'run', '-d', '--name', client, '--privileged', '--device', '/dev/net/tun',
                    '--entrypoint', 'sh', args.tool_image, '-c', 'exec sleep 1800')
            def app(*parts, **kw):
                return inside('docker', 'exec', '-i', client, *parts, **kw)
            endpoint = command('docker', 'inspect', '-f', '{{(index .NetworkSettings.Networks "bridge").IPAddress}}', protocol)
            client_native = ('[Interface]\nPrivateKey = '+client_key.decode()+'\n'+extensions+'[Peer]\nPublicKey = '+request['settings']['server_pub_key']+
                             '\nEndpoint = '+endpoint+':51820\nAllowedIPs = 0.0.0.0/0, ::/0\n')
            app('sh', '-ec', 'umask 077; cat > /native.conf', data=client_native.encode())
            if tool == 'wg': app('ip', 'link', 'add', iface, 'type', 'wireguard')
            else: app('amneziawg-go', iface)
            app(tool, 'setconf', iface, '/native.conf')
            app('ip', 'addr', 'add', subnet+'.2/32', 'dev', iface)
            app('ip', 'link', 'set', iface, 'up')
            app('ip', 'route', 'add', '198.51.100.1/32', 'dev', iface)
            stream = pipe('docker', 'exec', '-i', client, 'python3', '-u', '-c', CLIENT)
            identity = json.loads(stream.stdout.readline())
            def retained(label):
                stream.stdin.write(label+'\n');stream.stdin.flush()
                assert stream.stdout.readline().strip() == 'SAME_TCP'
            retained('before')
            attempts = []
            expected = ['applied'] if tool == 'wg' else ['unavailable', 'applied']
            if tool == 'awg':
                pid = int(command('cat', '/run/provider.pid'))
                assert b'/provider.py' in inside('cat', f'/proc/{pid}/cmdline').stdout
                command('kill', '-TERM', str(pid));assert tls.wait(timeout=15) == 143 or tls.returncode == 0
            for desired in expected:
                if desired == 'applied' and tool == 'awg': tls = serve_tls()
                host_pid = run('docker', 'inspect', '-f', '{{.State.Pid}}', fixture).stdout.decode().strip()
                replacements = {'fixture': fixture, 'pid': host_pid, 'protocol': protocol, 'expected': desired}
                invocation = [part for part in runner]
                for key, value in replacements.items(): invocation = [p.replace('{'+key+'}', value) for p in invocation]
                result = run(*invocation, timeout=360, check=False)
                text = result.stdout.decode(errors='replace')
                print(text, flush=True)
                if result.returncode:
                    print(result.stderr.decode(errors='replace'), flush=True)
                    raise RuntimeError('application IPv6 preparation failed; see Qt output above')
                assert 'IPV6_ACTIVATION_RESULT' in text
                retained('after-'+desired)
                attempts.append(desired)
                assert vpn('test', '!', '-e', '/run/forbidden-startup-body').returncode == 0
            peer_rows = vpn(tool, 'show', iface, 'allowed-ips').stdout.decode().splitlines()
            assigned = next(line.split()[1:] for line in peer_rows if line.split()[0] == client_public)
            address = next(value.strip(',') for value in assigned if ':' in value).split('/')[0]
            app('ip', '-6', 'addr', 'add', address+'/128', 'dev', iface, 'nodad')
            app('ip', '-6', 'route', 'add', '2606:4700:4700::1111/128', 'dev', iface)
            app('sh', '-ec', 'mkdir -p /etc/ssl/certs; cat > /etc/ssl/certs/ca-certificates.crt', data=cert)
            probe = "import socket,ssl,json; s=ssl.create_default_context().wrap_socket(socket.create_connection(('2606:4700:4700::1111',443),10),server_hostname='cloudflare-dns.com'); s.sendall(b'GET /dns-query?name=.&type=NS HTTP/1.0\\r\\nHost: cloudflare-dns.com\\r\\n\\r\\n'); data=b''\nwhile True:\n p=s.recv(4096)\n if not p:break\n data+=p\nassert b'200 OK' in data and json.loads(data.split(b'\\r\\n\\r\\n',1)[1])['Status']==0\nprint('ENCRYPTED_IPV6_TLS_PASS')"
            assert b'ENCRYPTED_IPV6_TLS_PASS' in app('python3', '-c', probe).stdout
            retained('after-ipv6')
            report['protocols'][protocol] = {'application_attempts': attempts, 'original_tcp_port': identity['port'],
                                             'same_ipv4_tcp': True, 'encrypted_ipv6_tls': True, 'startup_body_executed': False}
            stream.stdin.close();assert stream.wait(timeout=15) == 0
        observations = [json.loads(line) for line in command('cat', '/run/provider-observations.jsonl').splitlines()]
        assert len(observations) >= 4 and all(row['source'] == '2001:db8:99::2' for row in observations), observations
        report['outside_source_after_two_nat_layers'] = '2001:db8:99::2'
        report['authenticated_https_requests'] = len(observations)
        report['result'] = 'PASS'
    finally:
        run('docker', 'rm', '-f', '-v', fixture, check=False)
        for child in children:
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: child.kill();child.wait(timeout=10)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
