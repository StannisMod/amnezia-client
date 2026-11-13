"""Real OpenVPN TLS tunnel using the production server configuration resource.

Run only in a disposable Docker network namespace with no external interfaces.
Fixture certificates, DH mode and Unix group are local test substitutions.
"""
import json
import hashlib
import os
import select
from pathlib import Path
import subprocess
import time

def run(*args, **kwargs):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30, **kwargs)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f'{args!r}: {error.output}') from error

assert {r['ifname'] for r in json.loads(run('ip', '-j', 'link'))} == {'lo'}, 'requires --network none'
run('ip', 'link', 'set', 'lo', 'up')
source_root = Path(os.environ.get('AMNEZIA_OPENVPN_SOURCE_ROOT', '/src'))
openvpn_binary = os.environ.get('AMNEZIA_OPENVPN_BINARY', 'openvpn')
root = Path('/opt/amnezia/openvpn')
root.mkdir(parents=True, exist_ok=True)
print(run(openvpn_binary,'--version').splitlines()[0],flush=True)
processes = []
logs = []
names = ('ovpn-client', 'ovpn-origin')
try:
    for name in names:
        run('ip', 'netns', 'add', name)
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
    for device, peer, ns, local, remote, family in (
        ('outer0', 'client0', names[0], '198.51.100.1/24', '198.51.100.2/24', '-4'),
        ('uplink0', 'origin0', names[1], 'fd88::2/64', 'fd88::1/64', '-6'),
    ):
        run('ip', 'link', 'add', device, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', ns)
        run('ip', 'link', 'set', device, 'up')
        run('ip', '-n', ns, 'link', 'set', peer, 'up')
        run('ip', family, 'addr', 'add', local, 'dev', device, *(['nodad'] if family == '-6' else []))
        run('ip', '-n', ns, family, 'addr', 'add', remote, 'dev', peer, *(['nodad'] if family == '-6' else []))
    run('ip', '-6', 'route', 'add', 'default', 'via', 'fd88::1', 'dev', 'uplink0')
    policy_file = os.environ.get('AMNEZIA_OPENVPN_CLIENT_POLICIES')
    policy_mode = os.environ.get('AMNEZIA_OPENVPN_POLICY_MODE', 'full')
    native_policy = 'client\nremote 198.51.100.1 1194\n'
    if policy_file:
        policy_bytes = Path(policy_file).read_bytes()
        print('Qt policy SHA256:',hashlib.sha256(policy_bytes).hexdigest(),'mode:',policy_mode,flush=True)
        native_policy = json.loads(policy_bytes)[policy_mode]
        # The fixture supplies certificates and DNS independently; retain every routing option.
        native_policy = '\n'.join(line for line in native_policy.splitlines()
            if not line.startswith(('up ', 'down ', 'script-security ')))
        run('ip', 'link', 'add', 'native0', 'type', 'veth', 'peer', 'name', 'direct0')
        run('ip', 'link', 'set', 'native0', 'netns', names[0])
        run('ip', 'link', 'set', 'direct0', 'netns', names[1])
        for ns, dev, addr in ((names[0], 'native0', 'fd99::2/64'), (names[1], 'direct0', 'fd99::1/64')):
            run('ip', '-n', ns, 'link', 'set', dev, 'up')
            run('ip', '-n', ns, '-6', 'addr', 'add', addr, 'dev', dev, 'nodad')
        run('ip', '-n', names[0], '-6', 'route', 'add', 'default', 'via', 'fd99::1', 'dev', 'native0')
        run('ip', '-n', names[0], '-4', 'route', 'add', 'default', 'via', '198.51.100.1', 'dev', 'client0')
        for addr in ('2001:db8:88::1/128', '64:ff9b::c000:201/128'):
            run('ip', '-n', names[1], '-6', 'addr', 'add', addr, 'dev', 'origin0', 'nodad')

    run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-days', '1', '-subj', '/CN=Isolated OpenVPN CA', '-keyout', str(root/'ca.key'), '-out', str(root/'ca.crt'))
    for name, usage in (('server', 'serverAuth'), ('client', 'clientAuth')):
        run('openssl', 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-subj', '/CN='+name, '-keyout', str(root/(name+'.key')), '-out', str(root/(name+'.csr')))
        (root/(name+'.ext')).write_text('keyUsage=critical,digitalSignature,keyAgreement\nextendedKeyUsage='+usage+'\n')
        run('openssl', 'x509', '-req', '-in', str(root/(name+'.csr')), '-CA', str(root/'ca.crt'),
            '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(root/(name+'.ext')),
            '-out', str(root/(name+'.crt')))
    (root/'AmneziaReq.crt').write_bytes((root/'server.crt').read_bytes())
    (root/'AmneziaReq.key').write_bytes((root/'server.key').read_bytes())
    env = dict(os.environ, OPENVPN_PORT='1194', OPENVPN_TRANSPORT_PROTO='udp', OPENVPN_SUBNET_IP='10.66.0.0',
               OPENVPN_SUBNET_MASK='255.255.255.0', OPENVPN_NCP_DISABLE='', OPENVPN_CIPHER='AES-256-GCM',
               OPENVPN_HASH='SHA256', OPENVPN_TLS_AUTH='', OPENVPN_ADDITIONAL_SERVER_CONFIG='')
    run('bash', str(source_root/'client/server_scripts/openvpn/configure_container.sh'), env=env)
    config = (root/'server.conf').read_text().replace('dh /opt/amnezia/openvpn/dh.pem', 'dh none')
    config = config.replace('group nobody', 'group nogroup').replace('crl-verify /opt/amnezia/openvpn/crl.pem', '')
    (root/'server.conf').write_text(config)
    (root/'client.conf').write_text(f'''{native_policy}
dev tun0
proto udp
nobind
ca {root}/ca.crt
cert {root}/client.crt
key {root}/client.key
remote-cert-tls server
data-ciphers AES-256-GCM
auth SHA256
verb 3
''')
    for name, prefix in (('server', []), ('client', ['ip', 'netns', 'exec', names[0]])):
        log = (root/(name+'.log')).open('w'); logs.append(log)
        processes.append(subprocess.Popen([*prefix, openvpn_binary, '--config', str(root/(name+'.conf'))], stdout=log, stderr=subprocess.STDOUT))
    deadline = time.monotonic()+15
    while time.monotonic() < deadline:
        if 'Initialization Sequence Completed' in (root/'client.log').read_text(): break
        if any(p.poll() is not None for p in processes): raise RuntimeError('OpenVPN exited: '+(root/'server.log').read_text()+(root/'client.log').read_text())
        time.sleep(.1)
    else: raise RuntimeError('OpenVPN TLS handshake timed out: '+(root/'client.log').read_text())
    addresses = json.loads(run('ip', '-n', names[0], '-j', '-6', 'addr', 'show', 'dev', 'tun0'))
    assert any(a['scope']=='global' for r in addresses for a in r['addr_info']), 'production OpenVPN server supplied no tunnel IPv6 address'
    echo4 = """import socket,threading
def serve(c):
 while True:
  data=c.recv(1024)
  if not data:break
  c.sendall(data)
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.66.0.1',18080));s.listen()
while True:
 c,a=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
"""
    processes.append(subprocess.Popen(['python3', '-u', '-c', echo4]))
    old4 = """import socket,sys,time
time.sleep(.1)
sockets=[socket.create_connection(('10.66.0.1',18080),3) for _ in range(2)]
for s in sockets:s.sendall(b'before');assert s.recv(6)==b'before'
print('READY',flush=True)
assert sys.stdin.readline().strip()=='continue'
for s in sockets:s.sendall(b'after');assert s.recv(5)==b'after'
print('ORIGINAL_TCP_RETAINED',flush=True)
"""
    observer = subprocess.Popen(['ip','netns','exec',names[0],'python3','-u','-c',old4],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    processes.append(observer)
    assert select.select([observer.stdout], [], [], 5)[0] and observer.stdout.readline().strip()=='READY', 'original IPv4 TCP setup failed'
    before4=run('ip','-4','route','show','table','all')+run('iptables','-S')+run('iptables','-t','nat','-S')
    run('ip', '-6', 'route', 'delete', 'default')
    missing = subprocess.run(['bash', '-ec', '. "$1"; amnezia_enable_ipv6 tun0 required', 'sh', str(source_root/'client/server_scripts/enable_ipv6_forwarding.sh')],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
    assert missing.returncode == 1 and 'no-egress-route' in missing.stdout, missing.stdout
    run('ip', '-n', names[0], '-6', 'route', 'add', '2001:db8:6666::1/128', 'dev', 'tun0')
    unavailable = """import errno,socket,time
start=time.monotonic()
try:socket.create_connection(('2001:db8:6666::1',443),3)
except OSError as e:assert e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH),repr(e)
else:raise AssertionError('IPv4-only server unexpectedly reached IPv6 origin')
assert time.monotonic()-start<1.5,'missing IPv6 route caused a TCP timeout'
"""
    run('ip','netns','exec',names[0],'python3','-c',unavailable)
    run('ip', '-n', names[0], '-6', 'route', 'delete', '2001:db8:6666::1/128', 'dev', 'tun0')
    run('ip', '-6', 'route', 'add', 'default', 'via', 'fd88::1', 'dev', 'uplink0')
    run('bash', '-ec', '. "$1"; amnezia_enable_ipv6 tun0 required', 'sh', str(source_root/'client/server_scripts/enable_ipv6_forwarding.sh'))
    assert before4==run('ip','-4','route','show','table','all')+run('iptables','-S')+run('iptables','-t','nat','-S'), 'IPv6 preparation changed IPv4 state'
    observer.stdin.write('continue\n');observer.stdin.flush()
    assert select.select([observer.stdout], [], [], 5)[0] and observer.stdout.readline().strip()=='ORIGINAL_TCP_RETAINED', 'original IPv4 TCP was lost'

    # A distinct namespace owns the origin; the client has no IPv6 route to it outside OpenVPN.
    echo = '''import socket,threading,sys
def udp(address):
 u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.bind((address,18081))
 while True:
  data,a=u.recvfrom(4096);u.sendto(a[0].encode() if data==b'PATH' else data,a)
for address in sys.argv[1:]:threading.Thread(target=udp,args=(address,),daemon=True).start()
def tcp(c,peer):
 try:
  c.sendall(peer.encode())
  while c.recv(4096):c.sendall(peer.encode())
 except OSError:pass
 finally:c.close()
s=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('::',18081));s.listen()
while True:
 c,a=s.accept();threading.Thread(target=tcp,args=(c,a[0]),daemon=True).start()
'''
    processes.append(subprocess.Popen(['ip', 'netns', 'exec', names[1], 'python3', '-u', '-c', echo, 'fd88::1', *(['2001:db8:88::1','64:ff9b::c000:201'] if policy_file else [])]))
    if not policy_file: run('ip', '-n', names[0], '-6', 'route', 'add', 'fd88::/64', 'dev', 'tun0')
    probe = "import socket,time;time.sleep(.1);s=socket.create_connection(('fd88::1',18081),3);assert s.recv(64)==b'fd88::2';u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.settimeout(3);u.sendto(b'OPENVPN_IPV6_UDP',('fd88::1',18081));assert u.recv(64)==b'OPENVPN_IPV6_UDP'"
    if not policy_file:
        run('ip', 'netns', 'exec', names[0], 'python3', '-c', probe)
    else:
        for destination in ('fd88::1', '2001:db8:88::1', '64:ff9b::c000:201'):
            tunneled = policy_mode == 'full' or (destination == 'fd88::1') == (policy_mode == 'include')
            expected = 'fd88::2' if tunneled else 'fd99::2'
            check = """import socket,sys,time
time.sleep(.1)
target,expected=sys.argv[1:]
s=socket.create_connection((target,18081),3);actual=s.recv(64).decode();assert actual==expected,repr((target,actual,expected,'TCP'))
u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.settimeout(3);u.sendto(b'PATH',(target,18081));actual=u.recv(64).decode();assert actual==expected,repr((target,actual,expected,'UDP'))
"""
            run('ip', 'netns', 'exec', names[0], 'python3', '-c', check, destination, expected)
        print('PASS: Qt-generated '+policy_mode+' profile selects correct IPv6 TCP/UDP paths for GUA/ULA/NAT64',flush=True)
    route_fixture = os.environ.get('AMNEZIA_OPENVPN_ROUTE_FIXTURE')
    if route_fixture and policy_file and policy_mode == 'full':
        old6 = """import socket,sys
s=socket.create_connection(('2001:db8:88::1',18081),3);assert s.recv(64)==b'fd88::2'
print('READY',flush=True)
assert sys.stdin.readline().strip()=='continue'
s.sendall(b'old-socket');assert s.recv(64)==b'fd88::2'
print('ORIGINAL_IPV6_TCP_RETAINED',flush=True)
"""
        original6 = subprocess.Popen(['ip','netns','exec',names[0],'python3','-u','-c',old6],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        processes.append(original6)
        assert select.select([original6.stdout],[],[],5)[0] and original6.stdout.readline().strip()=='READY'
        # DAD can add the automatic link-local anycast route after OpenVPN has
        # reported ready. Snapshot a settled tunnel, not that unrelated transition.
        settled = time.monotonic() + 5
        while True:
            rows = json.loads(run('ip','-n',names[0],'-j','-6','addr','show'))
            tentative = any(entry.get('tentative', False) or 'tentative' in entry.get('flags', [])
                            for row in rows for entry in row['addr_info'])
            if not tentative: break
            assert time.monotonic() < settled, 'IPv6 tunnel DAD did not settle'
            time.sleep(.05)
        before6 = run('ip','-n',names[0],'-6','rule','show') + run('ip','-n',names[0],'-6','route','show','table','all')
        route_env=dict(os.environ,AMNEZIA_IPV6_LAB='isolated-namespace')
        route_env['LD_LIBRARY_PATH']=os.environ.get('AMNEZIA_OPENVPN_QT_LIBRARY_PATH','/opt/AmneziaVPN/lib:/opt/AmneziaVPN/bin')
        updater = subprocess.Popen(['ip','netns','exec',names[0],route_fixture],env=route_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        processes.append(updater)
        assert select.select([updater.stdout],[],[],5)[0] and updater.stdout.readline().strip()=='READY'
        addresses=json.loads(run('ip','-n',names[0],'-j','-4','addr','show','dev','tun0'))
        local4=addresses[0]['addr_info'][0]['local']
        updater.stdin.write(json.dumps({'local_ipv4':local4,'hosts':['2001:db8:88::1'],'through_vpn':False})+'\n');updater.stdin.flush()
        assert select.select([updater.stdout],[],[],10)[0] and updater.stdout.readline().strip()=='OK'
        original6.stdin.write('continue\n');original6.stdin.flush()
        assert select.select([original6.stdout],[],[],5)[0] and original6.stdout.readline().strip()=='ORIGINAL_IPV6_TCP_RETAINED'
        run('ip','netns','exec',names[0],'python3','-c',check,'2001:db8:88::1','fd99::2')
        updater.stdin.close();assert updater.wait(timeout=10)==0
        after6=run('ip','-n',names[0],'-6','rule','show')+run('ip','-n',names[0],'-6','route','show','table','all')
        if before6 != after6:
            import difflib
            print(''.join(difflib.unified_diff(before6.splitlines(True),after6.splitlines(True))),flush=True)
        assert before6==after6,'dynamic IPv6 rules/routes leaked after updater exit'
        print('PASS: dynamic DIRECT IPv6 route changes new TCP/UDP path while original VPN TCP survives; owned policy cleans up',flush=True)
    print('PASS: real OpenVPN TLS forwards IPv6 TCP/UDP, retains two original IPv4 TCP sockets and IPv4 state; missing egress fails fast', flush=True)
except Exception:
    for command in (['ip','-6','route','show','table','all'],
                    ['ip','-n',names[0],'-6','route','show','table','all'],
                    ['ip','-n',names[1],'-6','route','show','table','all'],
                    ['ip6tables','-t','nat','-nvL'], ['ip6tables','-nvL']):
        diagnostic=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(command,diagnostic.stdout,flush=True)
    print((root/'server.log').read_text(),(root/'client.log').read_text(),flush=True)
    raise
finally:
    for process in reversed(processes): process.terminate()
    for process in reversed(processes):
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
    for log in logs: log.close()
    for name in names: subprocess.run(['ip', 'netns', 'delete', name], check=False)
