"""Real quick/TUN/container restart acceptance in the disposable Docker daemon."""
import json
import time


def test_restarts(inside, image, root):
    def write(container, path, value):
        inside('docker', 'exec', '-i', container, 'sh', '-ec',
               'umask 077; mkdir -p "$(dirname "$1")"; cat > "$1"', 'sh', path, data=value)

    def public(private):
        return inside('docker', 'run', '--rm', '-i', '--network', 'none', '--entrypoint', 'wg', image,
                      'pubkey', data=private+'\n').stdout.strip()

    echo = '''import socketserver,socket
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(65536)
   if not data: return
   self.request.sendall(data)
class Server(socketserver.ThreadingTCPServer):
 address_family=socket.AF_INET6
 def server_bind(self):
  self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
  super().server_bind()
Server(('::',18084),Echo).serve_forever()
'''
    probe = '''import socket,time,sys
deadline=time.monotonic()+30
for host in sys.argv[1:]:
 while True:
  try:
   s=socket.create_connection((host,18084),timeout=5)
   payload=bytes(range(256))*256;s.sendall(payload);received=b''
   while len(received)<len(payload):
    part=s.recv(len(payload)-len(received));assert part;received+=part
   assert received==payload;s.close();break
  except (OSError,AssertionError):
   if time.monotonic()>=deadline: raise
   time.sleep(.2)
print('PASS_ENCRYPTED_DUAL_STACK_TCP',flush=True)
'''
    results = []
    for kind, binary, iface in (('wireguard','wg','wg0'), ('awg','awg','awg0')):
        server = 'amnezia-wireguard' if kind == 'wireguard' else 'amnezia-awg2'
        client = 'fixture-restart-client'
        origin = 'fixture-restart-origin'
        private = inside('docker','run','--rm','--network','none','--entrypoint','wg',image,'genkey').stdout.strip()
        client_private = inside('docker','run','--rm','--network','none','--entrypoint','wg',image,'genkey').stdout.strip()
        server_public, client_public = public(private), public(client_private)
        parameters = '' if kind == 'wireguard' else 'Jc = 3\nJmin = 50\nJmax = 100\nS1 = 16\nS2 = 24\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\n'
        server_config = f'[Interface]\nPrivateKey = {private}\nAddress = 10.77.0.1/24, fd77::1/64\nListenPort = 51820\nMTU = 1280\n{parameters}\n[Peer]\nPublicKey = {client_public}\nAllowedIPs = 10.77.0.2/32, fd77::2/128\n'
        client_config = f'[Interface]\nPrivateKey = {client_private}\nAddress = 10.77.0.2/32, fd77::2/128\nMTU = 1280\n{parameters}\n[Peer]\nPublicKey = {server_public}\nEndpoint = {server}:51820\nAllowedIPs = 10.77.0.1/32, fd77::1/128\nPersistentKeepalive = 1\n'
        folder = 'wireguard' if kind == 'wireguard' else 'awg'
        path = f'/opt/amnezia/{folder}/{iface}.conf'
        try:
            for name, script in (
                (server, 'while [ ! -f /configured ]; do sleep .05; done; python3 /opt/amnezia/fixture-echo.py & exec /bin/bash /opt/amnezia/start.sh'),
                (client, f'while [ ! -f /configured ]; do sleep .05; done; {binary}-quick up /opt/amnezia/client0.conf; exec tail -f /dev/null'),
            ):
                inside('docker','run','-d','--init','--privileged','--network','amnezia-dns-net','--name',name,
                       '--sysctl','net.ipv6.conf.all.disable_ipv6=0','--entrypoint','sh',image,'-ec',script)
            origin_echo=echo.replace('  while True:',"  print('REMOTE='+self.client_address[0],flush=True)\n  while True:",1)
            inside('docker','run','-d','--init','--network','amnezia-ipv6-egress','--name',origin,
                   '--sysctl','net.ipv6.conf.all.disable_ipv6=0','--entrypoint','python3',image,'-u','-c',origin_echo)
            origin_v6=json.loads(inside('docker','inspect',origin).stdout)[0]['NetworkSettings']['Networks']['amnezia-ipv6-egress']['GlobalIPv6Address']
            assert origin_v6
            client_config=client_config.replace('AllowedIPs = 10.77.0.1/32, fd77::1/128',f'AllowedIPs = 10.77.0.1/32, fd77::1/128, {origin_v6}/128')
            inside('sh','-c','. /prepare_ipv6_network.sh; amnezia_attach_ipv6_network "$1"','sh',server)
            print(json.dumps({'protocol':kind,'phase':'attached','networks':list(json.loads(inside('docker','inspect',server).stdout)[0]['NetworkSettings']['Networks'])}),flush=True)
            startup = (root/f'client/server_scripts/{kind}/start.sh').read_text()
            for variable, value in (('$WIREGUARD_SUBNET_IP','10.77.0.0'),('$AWG_SUBNET_IP','10.77.0.0'),('$WIREGUARD_SUBNET_CIDR','24'),('$SERVER_IP_ADDRESS','203.0.113.7')):
                startup = startup.replace(variable,value)
            first, body = startup.split('\n',1)
            startup = first+'\n'+(root/'client/server_scripts/enable_ipv6_forwarding.sh').read_text()+'\n'+body
            write(server,'/opt/amnezia/start.sh',startup)
            write(server,path,server_config)
            write(server,'/opt/amnezia/fixture-echo.py',echo)
            for name in ('controller.py','supervisor.py'):
                write(server,'/opt/amnezia/mtu/current/'+name,(root/'server/mtu'/name).read_text())
            write(client,'/opt/amnezia/client0.conf',client_config)
            inside('docker','exec',server,'touch','/configured')
            inside('docker','exec',client,'touch','/configured')
            outer = json.loads(inside('docker','inspect',server).stdout)[0]['NetworkSettings']['Networks']['amnezia-dns-net']['IPAddress']
            phases = []
            for phase in ('initial','restart-with-ipv6','restart-without-ipv6-egress'):
                if phase == 'restart-without-ipv6-egress':
                    inside('docker','network','disconnect','amnezia-ipv6-egress',server)
                if phase != 'initial':
                    inside('docker','restart','--time','2',server)
                deadline = time.monotonic()+20
                while True:
                    observed_key=inside('docker','exec',server,binary,'show',iface,'public-key',check=False).stdout.strip()
                    snapshot=inside('docker','exec',server,'ip','-j','addr','show','dev',iface,check=False)
                    rows=json.loads(snapshot.stdout or '[]') if snapshot.returncode==0 else []
                    ready_addresses={row['local'] for row in rows[0]['addr_info']} if rows else set()
                    if observed_key==server_public and {'10.77.0.1','fd77::1'} <= ready_addresses:
                        break
                    if time.monotonic()>=deadline:
                        logs=inside('docker','logs',server)
                        raise RuntimeError('real server startup failed: '+logs.stdout+logs.stderr)
                    time.sleep(.1)
                assert inside('docker','exec',server,'cat',path).stdout == server_config
                assert inside('docker','exec',server,binary,'show',iface,'peers').stdout.strip() == client_public
                addresses=json.loads(inside('docker','exec',server,'ip','-j','addr','show','dev',iface).stdout)[0]['addr_info']
                assert {'10.77.0.1','fd77::1'} <= {row['local'] for row in addresses}
                link=json.loads(inside('docker','exec',server,'ip','-j','-d','link','show','dev',iface).stdout)[0]
                assert link['linkinfo']['info_kind'] == ('wireguard' if kind == 'wireguard' else 'tun')
                current_outer=json.loads(inside('docker','inspect',server).stdout)[0]['NetworkSettings']['Networks']['amnezia-dns-net']['IPAddress']
                assert current_outer == outer, 'restart changed original Docker IPv4 endpoint'
                if phase != 'restart-without-ipv6-egress':
                    defaults=json.loads(inside('docker','exec',server,'ip','-j','-6','route','show','default').stdout)
                    assert defaults and defaults[0]['dev'] != iface
                    egress=defaults[0]['dev']
                    inside('docker','exec',server,'ip6tables','-t','nat','-C','POSTROUTING','-s','fd77::1/64','-o',egress,'-j','MASQUERADE')
                    inside('docker','exec',server,'ip6tables','-C','FORWARD','-i',iface,'-o',egress,'-s','fd77::1/64','-j','ACCEPT')
                hosts=['10.77.0.1','fd77::1'] + ([origin_v6] if phase != 'restart-without-ipv6-egress' else [])
                outcome=inside('docker','exec',client,'python3','-c',probe,*hosts)
                if phase != 'restart-without-ipv6-egress':
                    source=json.loads(inside('docker','inspect',server).stdout)[0]['NetworkSettings']['Networks']['amnezia-ipv6-egress']['GlobalIPv6Address']
                    remote=inside('docker','logs',origin).stdout.splitlines()
                    assert remote and remote[-1] == 'REMOTE='+source, 'native encrypted egress was not masqueraded'

                assert 'PASS_ENCRYPTED_DUAL_STACK_TCP' in outcome.stdout
                assert any(int(line.split()[1])>0 for line in inside('docker','exec',server,binary,'show',iface,'latest-handshakes').stdout.splitlines())
                assert all(int(value)>0 for value in inside('docker','exec',server,binary,'show',iface,'transfer').stdout.split()[1:])
                print(json.dumps({'protocol':kind,'phase':phase,'networks':list(json.loads(inside('docker','inspect',server).stdout)[0]['NetworkSettings']['Networks'])}),flush=True)
                attached = json.loads(inside('docker','inspect',server).stdout)[0]['NetworkSettings']['Networks']
                assert ('amnezia-ipv6-egress' in attached) == (phase != 'restart-without-ipv6-egress')
                phases.append(phase)
            logs=inside('docker','logs',server)
            assert 'boot-preparation-failed' in logs.stderr
            results.append(dict(protocol=kind,phases=phases,result='PASS'))
            print('PASS: actual '+kind+' quick/TUN/container restarts preserve keys and restore encrypted IPv4/IPv6 TCP',flush=True)
        finally:
            inside('docker','rm','-f',client,server,origin,check=False)
    return results
