"""Real OpenVPN TLS tunnel using the production server configuration resource.

Run only in a disposable Docker network namespace with no external interfaces.
Fixture certificates, DH mode and Unix group are local test substitutions.
AMNEZIA_OPENVPN_CAPABILITY_TEST optionally points to the compiled test_connection
Qt executable. Its existing profile-learning test consumes this session's real
PUSH log while the original IPv4 sockets remain open.
"""
import json
import hashlib
import ipaddress
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
if os.environ.get('AMNEZIA_OPENVPN_IPC_SERVICE'):
    # Keep the fixture's QtRO sockets separate from an installed service that
    # may already be running in the disposable container's parent namespace.
    inputs=[source_root,Path(openvpn_binary),Path(os.environ['AMNEZIA_OPENVPN_IPC_SERVICE']),
            Path(os.environ['AMNEZIA_OPENVPN_ROUTE_FIXTURE']),Path(os.environ['AMNEZIA_OPENVPN_CLIENT_POLICIES'])]
    assert not any(path.resolve().is_relative_to('/tmp') for path in inputs), 'IPC fixture inputs must be outside its private /tmp'
    run('mount','-t','tmpfs','-o','mode=1777','tmpfs','/tmp')
    # The service also owns Mozilla's Unix socket under /run, independently of
    # its QtRO sockets in /tmp. Never unlink the parent installed service's
    # listener when starting the fixture's second service instance.
    Path('/var/run/amneziavpn').mkdir(parents=True, exist_ok=True)
    run('mount','-t','tmpfs','-o','mode=0755','tmpfs','/var/run/amneziavpn')

root = Path('/opt/amnezia/openvpn')
root.mkdir(parents=True, exist_ok=True)
print(run(openvpn_binary,'--version').splitlines()[0],flush=True)
processes = []
logs = []
rpc_updater = None
native6_before = None
names = ('ovpn-client', 'ovpn-origin')

def legacy_ipv6_acceptance(mode):
    # Native origins remain reachable outside the VPN. A timeout or a policy
    # string alone cannot prove that block-ipv6 stopped a bypass.
    peer = '''import socket,sys,threading
family,address,port,kind=sys.argv[1:];family=int(family);port=int(port)
def serve(c):
 try:
  if kind=='native':c.sendall(b'NATIVE');return
  while True:
   data=c.recv(4096)
   if not data:return
   c.sendall(data)
 finally:c.close()
if kind=='native':
 def udp(address,ready):
  s=socket.socket(family,socket.SOCK_DGRAM);s.bind((address,port))
  ready.set()
  while True:
   data,a=s.recvfrom(4096);s.sendto(b'NATIVE',a)
 for udpaddress in ('fd88::1','2001:db8:88::1','64:ff9b::c000:201'):
  ready=threading.Event()
  threading.Thread(target=udp,args=(udpaddress,ready),daemon=True).start()
  assert ready.wait(3),'UDP origin did not bind'
s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,port));s.listen()
print('READY',flush=True)
while True:
 c,a=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
'''
    for prefix, family, address, port, kind in (([], '2', '10.66.0.1', '18080', 'echo'),
            (['ip','netns','exec',names[1]], '10', '::', '18081', 'native')):
        process = subprocess.Popen([*prefix,'python3','-u','-c',peer,family,address,port,kind],stdout=subprocess.PIPE,text=True)
        processes.append(process)
        assert select.select([process.stdout],[],[],5)[0] and process.stdout.readline().strip()=='READY'
    probe = '''import errno,socket,sys,time
mode=sys.argv[1]
old=[socket.create_connection(('10.66.0.1',18080),3) for _ in range(2)]
for s in old:s.sendall(b'before');assert s.recv(6)==b'before'
for address in ('fd88::1','2001:db8:88::1','64:ff9b::c000:201'):
 blocked=mode in ('legacy-full','legacy-export','legacy-api') or ((address=='fd88::1')==(mode=='legacy-include'))
 for udp in (False,True):
  start=time.monotonic()
  try:
   with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
    # Linux treats ICMPv6 no-route as a soft UDP error unless the socket
    # requests its error queue. Observe the actual rejection, not a recv timeout.
    if udp:s.setsockopt(socket.IPPROTO_IPV6,getattr(socket,'IPV6_RECVERR',25),1)
    s.settimeout(3);s.connect((address,18081))
    if udp:s.send(b'probe')
    data=s.recv(64)
  except OSError as e:
   assert blocked and e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH),repr((address,udp,e))
   assert time.monotonic()-start<1.5,'blocked IPv6 timed out instead of failing fast'
  else:
   assert not blocked and data==b'NATIVE',repr(('IPv6 bypass',address,udp,data))
for s in old:s.sendall(b'after');assert s.recv(5)==b'after';s.close()
print('PASS: IPv4-only server blocks selected IPv6 TCP/UDP GUA/ULA/NAT64, preserves DIRECT exclusions and two original IPv4 TCP sockets',flush=True)
'''
    print(run('ip','netns','exec',names[0],'python3','-c',probe,mode),flush=True)

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
    # Exercise migration of an existing IPv4 server, not just the fresh template.
    legacy = '\n'.join(line for line in config.split('\n') if not line.startswith('server-ipv6 '))
    (root/'server.conf').write_text(legacy)
    (root/'server.conf').chmod(0o600)
    identities = {path:hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in root.iterdir() if path.suffix in ('.key','.crt')}
    migration = source_root/'client/server_scripts/openvpn/migrate_ipv6.sh'
    migrate = ['bash','-ec','. "$1"; amnezia_prepare_openvpn_ipv6 "$2"','sh',str(migration),str(root/'server.conf')]
    run(*migrate)
    migrated = (root/'server.conf').read_bytes()
    assert migrated.startswith(legacy.encode()) and migrated.count(b'\nserver-ipv6 ')==1
    assert (root/'server.conf').stat().st_mode & 0o777 == 0o600
    run(*migrate)
    assert (root/'server.conf').read_bytes()==migrated,'IPv6 migration is not idempotent'
    assert all(hashlib.sha256(path.read_bytes()).hexdigest()==value for path,value in identities.items()),'migration changed existing identity'
    custom = root/'custom.conf'
    custom.write_text('server 10.77.0.0 255.255.255.0\nserver-ipv6 fd77::/64 # administrator pool\n')
    custom_before = custom.read_bytes()
    run(*migrate[:-1],str(custom))
    assert custom.read_bytes()==custom_before,'migration replaced administrator IPv6 pool'
    print('PASS: existing IPv4 server migrated idempotently; identities, permissions and custom IPv6 pool preserved',flush=True)
    if policy_mode.startswith('legacy-'):
        (root/'server.conf').write_text(legacy)
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
    capability_test = os.environ.get('AMNEZIA_OPENVPN_CAPABILITY_TEST')
    if capability_test:
        with (root/'client.conf').open('a') as config_file: config_file.write('\nverb 4\n')
    ipc_service = os.environ.get('AMNEZIA_OPENVPN_IPC_SERVICE')
    def rpc_request(updater, message, expected='OK'):
        updater.stdin.write(json.dumps(message)+'\n');updater.stdin.flush()
        assert select.select([updater.stdout],[],[],12)[0], 'IPC fixture response timed out'
        reply=updater.stdout.readline().strip()
        assert reply==expected, ('IPC fixture response',reply,expected)
    for name, prefix in (('server', []), ('client', ['ip', 'netns', 'exec', names[0]])):
        if name == 'client' and ipc_service:
            assert policy_file and os.environ.get('AMNEZIA_OPENVPN_ROUTE_FIXTURE')
            with (root/'client.conf').open('a') as config_file:config_file.write('\nlog '+str(root/'client.log')+'\n')
            # Sequential installed-package cases reuse this directory. Clear
            # readiness from the previous session before starting the child.
            (root/'client.log').write_text('')
            service_log=(root/'service.log').open('w');logs.append(service_log)
            service_env=dict(os.environ,LD_LIBRARY_PATH=os.environ.get('AMNEZIA_OPENVPN_QT_LIBRARY_PATH','/opt/AmneziaVPN/lib:/opt/AmneziaVPN/bin'))
            processes.append(subprocess.Popen([*prefix,'unshare','--pid','--fork','--mount-proc','--kill-child=SIGKILL',ipc_service,'--console'],env=service_env,cwd=root,stdout=service_log,stderr=subprocess.STDOUT))
            service_env['AMNEZIA_IPV6_LAB']='isolated-namespace'
            rpc_updater=subprocess.Popen([*prefix,os.environ['AMNEZIA_OPENVPN_ROUTE_FIXTURE'],'--ipc-process'],env=service_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            processes.append(rpc_updater)
            assert select.select([rpc_updater.stdout],[],[],20)[0] and rpc_updater.stdout.readline().strip()=='READY','service process replica did not start'
            rpc_request(rpc_updater,{'local_ipv4':'198.51.100.2','hosts':['2001:db8:88::1'],'through_vpn':False},'FAIL')
            # A pre-existing interface with the old conventional name is not
            # owned by this process and must survive both graceful and hard exit.
            run('ip','-n',names[0],'link','add','tun0','type','dummy')
            run('ip','-n',names[0],'link','set','tun0','up')
            run('ip','-n',names[0],'-6','addr','add','fd55::1/64','dev','tun0','nodad')
            deadline=time.monotonic()+5
            while any(e.get('tentative',False) for r in json.loads(run('ip','-n',names[0],'-j','-6','addr','show')) for e in r['addr_info']):
                assert time.monotonic()<deadline,'native IPv6 DAD did not settle'
                time.sleep(.05)
            native6_before=run('ip','-n',names[0],'-6','rule','show')+run('ip','-n',names[0],'-6','route','show','table','all')
            rpc_request(rpc_updater,{'operation':'start','config':str(root/'client.conf')})
            continue
        log = (root/(name+'.log')).open('w'); logs.append(log)
        processes.append(subprocess.Popen([*prefix, openvpn_binary, '--config', str(root/(name+'.conf'))], cwd=root, stdout=log, stderr=subprocess.STDOUT))
    deadline = time.monotonic()+15
    while time.monotonic() < deadline:
        if 'Initialization Sequence Completed' in (root/'client.log').read_text(): break
        if any(p.poll() is not None for p in processes): raise RuntimeError('OpenVPN exited: '+(root/'server.log').read_text()+(root/'client.log').read_text())
        time.sleep(.1)
    else: raise RuntimeError('OpenVPN TLS handshake timed out: '+(root/'client.log').read_text())
    if policy_mode.startswith('legacy-'):
        legacy_ipv6_acceptance(policy_mode)
        raise SystemExit(0)
    client_links = json.loads(run('ip', '-n', names[0], '-j', '-6', 'addr', 'show'))
    # OpenVPN 2.6 net30 and 2.7 DCO/subnet allocate different IPv4 addresses.
    # Find the actual tunnel using the negotiated IPv6 pool, not a fixed .2.
    client_pool = ipaddress.IPv6Network('fd6e:a81b:704f:1101::/64')
    client_tun = next(link['ifname'] for link in client_links
                      if 'POINTOPOINT' in link['flags'] and any(
                          ipaddress.IPv6Address(address['local']) in client_pool for address in link['addr_info']))
    if ipc_service:
        print('Owned OpenVPN interface:',run('ip','-n',names[0],'-d','-j','link','show','dev',client_tun).strip(),flush=True)
    addresses = json.loads(run('ip', '-n', names[0], '-j', '-6', 'addr', 'show', 'dev', client_tun))
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
    if capability_test:
        probe_env = dict(os.environ, QT_QPA_PLATFORM='offscreen',
                         AMNEZIA_OPENVPN_PUSH_LOG=str(root/'client.log'),
                         AMNEZIA_OPENVPN_CLIENT_PROFILE=str(root/'client.conf'))
        print(run(capability_test, 'openVpnLearnsCapabilityWithoutReplacingImportedIdentity', env=probe_env), flush=True)
        print('PASS: real authenticated server PUSH parsed and capability saved for unchanged profiles with original IPv4 TCP open', flush=True)
    before4=run('ip','-4','route','show','table','all')+run('iptables','-S')+run('iptables','-t','nat','-S')
    run('ip', '-6', 'route', 'delete', 'default')
    missing = subprocess.run(['bash', '-ec', '. "$1"; amnezia_enable_ipv6 tun0 required', 'sh', str(source_root/'client/server_scripts/enable_ipv6_forwarding.sh')],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
    assert missing.returncode == 1 and 'no-egress-route' in missing.stdout, missing.stdout
    run('ip', '-n', names[0], '-6', 'route', 'add', '2001:db8:6666::1/128', 'dev', client_tun)
    unavailable = """import errno,socket,time
start=time.monotonic()
try:socket.create_connection(('2001:db8:6666::1',443),3)
except OSError as e:assert e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH),repr(e)
else:raise AssertionError('IPv4-only server unexpectedly reached IPv6 origin')
assert time.monotonic()-start<1.5,'missing IPv6 route caused a TCP timeout'
"""
    run('ip','netns','exec',names[0],'python3','-c',unavailable)
    run('ip', '-n', names[0], '-6', 'route', 'delete', '2001:db8:6666::1/128', 'dev', client_tun)
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
    if not policy_file: run('ip', '-n', names[0], '-6', 'route', 'add', 'fd88::/64', 'dev', client_tun)
    probe = "import socket,time;time.sleep(.1);s=socket.create_connection(('fd88::1',18081),3);assert s.recv(64)==b'fd88::2';u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.settimeout(3);u.sendto(b'OPENVPN_IPV6_UDP',('fd88::1',18081));assert u.recv(64)==b'OPENVPN_IPV6_UDP'"
    if not policy_file:
        run('ip', 'netns', 'exec', names[0], 'python3', '-c', probe)
    else:
        for destination in ('fd88::1', '2001:db8:88::1', '64:ff9b::c000:201'):
            tunneled = policy_mode in ('full', 'api-full') or (destination == 'fd88::1') == (policy_mode == 'include')
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
    if route_fixture and policy_file and policy_mode in ('full', 'include'):
        old_path = 'fd88::2' if policy_mode == 'full' else 'fd99::2'
        new_path = 'fd99::2' if policy_mode == 'full' else 'fd88::2'
        old6 = """import socket,sys
expected=sys.argv[1].encode()
s=socket.create_connection(('2001:db8:88::1',18081),3);s.settimeout(3);assert s.recv(64)==expected
print('READY',flush=True)
assert sys.stdin.readline().strip()=='continue'
s.sendall(b'old-socket');assert s.recv(64)==expected
print('ORIGINAL_IPV6_TCP_RETAINED',flush=True)
"""
        original6 = subprocess.Popen(['ip','netns','exec',names[0],'python3','-u','-c',old6,old_path],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
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
        before6 = native6_before if rpc_updater else run('ip','-n',names[0],'-6','rule','show') + run('ip','-n',names[0],'-6','route','show','table','all')
        route_env=dict(os.environ,AMNEZIA_IPV6_LAB='isolated-namespace')
        route_env['LD_LIBRARY_PATH']=os.environ.get('AMNEZIA_OPENVPN_QT_LIBRARY_PATH','/opt/AmneziaVPN/lib:/opt/AmneziaVPN/bin')
        updater = rpc_updater
        if not updater:
            updater = subprocess.Popen(['ip','netns','exec',names[0],route_fixture],env=route_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            processes.append(updater)
            assert select.select([updater.stdout],[],[],5)[0] and updater.stdout.readline().strip()=='READY'
        addresses=json.loads(run('ip','-n',names[0],'-j','-4','addr','show','dev',client_tun))
        local4=addresses[0]['addr_info'][0]['local']
        updater.stdin.write(json.dumps({'local_ipv4':local4,'hosts':['2001:db8:88::1'],'through_vpn':policy_mode == 'include'})+'\n');updater.stdin.flush()
        assert select.select([updater.stdout],[],[],10)[0] and updater.stdout.readline().strip()=='OK'
        original6.stdin.write('continue\n');original6.stdin.flush()
        assert select.select([original6.stdout],[],[],5)[0] and original6.stdout.readline().strip()=='ORIGINAL_IPV6_TCP_RETAINED'
        run('ip','netns','exec',names[0],'python3','-c',check,'2001:db8:88::1',new_path)
        if rpc_updater:rpc_request(updater,{'operation':os.environ.get('AMNEZIA_OPENVPN_STOP_OPERATION','stop')})
        updater.stdin.close();assert updater.wait(timeout=10)==0
        after6=run('ip','-n',names[0],'-6','rule','show')+run('ip','-n',names[0],'-6','route','show','table','all')
        if before6 != after6:
            import difflib
            print(''.join(difflib.unified_diff(before6.splitlines(True),after6.splitlines(True))),flush=True)
        assert before6==after6,'dynamic IPv6 rules/routes leaked after updater exit'
        if rpc_updater:
            assert json.loads(run('ip','-n',names[0],'-j','link','show','dev','tun0'))[0]['link_type']=='ether'
            print('PASS: '+os.environ.get('AMNEZIA_OPENVPN_STOP_OPERATION','stop')+' removes owned OpenVPN interface and preserves foreign tun0',flush=True)
        print('PASS: dynamic IPv6 route selects '+new_path+' for new TCP/UDP while original '+old_path+' TCP survives; owned policy cleans up',flush=True)
    print('PASS: real OpenVPN TLS forwards IPv6 TCP/UDP, retains two original IPv4 TCP sockets and IPv4 state; missing egress fails fast', flush=True)
except Exception:
    for command in (['ip','-6','route','show','table','all'],
                    ['ip','-n',names[0],'-6','route','show','table','all'],
                    ['ip','-n',names[1],'-6','route','show','table','all'],
                    ['ip6tables','-t','nat','-nvL'], ['ip6tables','-nvL']):
        diagnostic=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(command,diagnostic.stdout,flush=True)
    print((root/'server.log').read_text(),(root/'client.log').read_text(),flush=True)
    if (root/'service.log').exists():print((root/'service.log').read_text()[-65536:],flush=True)
    raise
finally:
    if rpc_updater and rpc_updater.poll() is None:
        try:
            rpc_request(rpc_updater,{'operation':'stop'})
            rpc_updater.stdin.close();rpc_updater.wait(timeout=5)
        except (OSError,AssertionError,subprocess.TimeoutExpired): pass
    for process in reversed(processes):
        if process.poll() is None: process.terminate()
    for process in reversed(processes):
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
    for log in logs: log.close()
    for name in names: subprocess.run(['ip', 'netns', 'delete', name], check=False)
