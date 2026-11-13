#!/usr/bin/env python3
"""Exercise packaged proxy IPv6 setup over SSH in an isolated Docker daemon.

Public numeric probe addresses terminate at a local TLS origin. No external
VPN, DNS queries, host routes, or host trust-store changes are involved.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

from test_activation import HTTPS, run

ORIGINS = r'''
import json,socket,threading,uuid
lock=threading.Lock()
def observation(kind,address):
 with lock:
  with open('/run/proxy-origins.jsonl','a') as f:f.write(json.dumps({'kind':kind,'source':address[0]})+'\n')
def connection(c,address):
 with c:
  identity=uuid.uuid4().hex;observation('tcp',address);f=c.makefile('rb')
  while True:
   line=f.readline(4096)
   if not line:return
   c.sendall(identity.encode()+b':'+line)
def accept(s):
 while True:
  c,a=s.accept();threading.Thread(target=connection,args=(c,a),daemon=True).start()
def packets(s):
 while True:
  data,a=s.recvfrom(65535);observation('udp',a);s.sendto(data,a)
for address in ('198.51.100.1','2001:db8:99::1'):
 for kind,port,worker in ((socket.SOCK_STREAM,18081,accept),(socket.SOCK_DGRAM,18082,packets)):
  s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,port))
  if kind==socket.SOCK_STREAM:s.listen()
  threading.Thread(target=worker,args=(s,),daemon=True).start()
print('READY',flush=True);threading.Event().wait()
'''

CLIENT = r'''
import socket,struct,json,sys
def exact(s,n):
 data=b''
 while len(data)<n:
  part=s.recv(n-len(data));assert part;data+=part
 return data
def address(s,kind):
 size={1:4,4:16}.get(kind)
 assert size
 ip=socket.inet_ntop(socket.AF_INET if kind==1 else socket.AF_INET6,exact(s,size));port=struct.unpack('!H',exact(s,2))[0]
 return ip,port
def request(command,ip,port):
 s=socket.create_connection(('127.0.0.1',39080),timeout=5);s.sendall(bytes([5,1,0]));assert exact(s,2)==bytes([5,0])
 family=socket.AF_INET6 if ':' in ip else socket.AF_INET;s.sendall(bytes([5,command,0,4 if family==socket.AF_INET6 else 1])+socket.inet_pton(family,ip)+struct.pack('!H',port))
 head=exact(s,4);assert head[:2]==bytes([5,0]);relay=address(s,head[3]);return s,relay
def exchange(s,data):
 s.sendall(data.encode()+b'\n');answer=b''
 while not answer.endswith(b'\n'):answer+=exact(s,1)
 identity,payload=answer.decode().rstrip('\n').split(':',1);assert payload==data;return identity
s,_=request(1,'198.51.100.1',18081);old=exchange(s,'before');local=s.getsockname()
print(json.dumps({'ready':True,'origin_id':old,'local_port':local[1]}),flush=True)
for line in sys.stdin:
 action=line.strip()
 if action=='ipv6':
  c,_=request(1,'2001:db8:99::1',18081);exchange(c,'ipv6');c.close();print('IPV6_TCP',flush=True)
 elif action=='udp6':
  control,relay=request(3,'0.0.0.0',0)
  if relay[0]=='0.0.0.0':relay=('127.0.0.1',relay[1])
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
   u.settimeout(5);header=bytes([0,0,0,4])+socket.inet_pton(socket.AF_INET6,'2001:db8:99::1')+struct.pack('!H',18082)
   u.sendto(header+b'udp-proof',relay);packet,_=u.recvfrom(4096);assert packet[:4]==bytes([0,0,0,4]) and packet[22:]==b'udp-proof'
  control.close();print('IPV6_UDP',flush=True)
 else:
  assert exchange(s,action)==old and s.getsockname()==local;print('SAME_TCP',flush=True)
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--tool-image',default='amnezia-local-vpn-tests')
    parser.add_argument('--proxy-image',default='amnezia-xray-ipv6:local')
    parser.add_argument('--tun-runner',type=Path,help='optional owned Linux TUN/service runner: FIXTURE SERVER_IPV6_SUBNET')
    parser.add_argument('runner',nargs=argparse.REMAINDER)
    args=parser.parse_args();runner=args.runner[1:] if args.runner[:1]==['--'] else args.runner
    assert runner,'supply the Qt test runner after --'
    fixture='amnezia-proxy-ipv6-'+uuid.uuid4().hex[:12]
    root=Path(__file__).resolve().parents[3]
    children=[];report={'schema_version':1,'scope':'isolated Docker, real SSH/curl/TLS/VLESS/Shadowsocks; not public Internet','protocols':{}}
    def inside(*parts,**kwargs):return run('docker','exec','-i',fixture,*parts,**kwargs)
    def command(*parts):return inside(*parts).stdout.decode().strip()
    def upload(data,path):inside('sh','-ec','umask 077; cat > "$1"','sh',path,data=data)
    def pipe(*parts):
        p=subprocess.Popen(['docker','exec','-i',fixture,*parts],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(p);return p
    def application(container,expected):
        pid=run('docker','inspect','-f','{{.State.Pid}}',fixture).stdout.decode().strip()
        argv=[part.format(fixture=fixture,pid=pid,protocol=container,expected=expected) for part in runner]
        result=run(*argv,check=False,timeout=120)
        print(result.stdout.decode(errors='replace'),end='',flush=True)
        if result.returncode and expected=='verified':
            for parts in (('docker','exec',container,'ip','-6','addr'),('docker','exec',container,'ip','-6','route'),
                          ('docker','network','inspect','amnezia-ipv6-egress'),('ip','-6','route')):
                detail=inside(*parts,check=False)
                print(detail.stdout.decode(errors='replace'),detail.stderr.decode(errors='replace'),flush=True)
            diagnostic=inside('docker','exec',container,'curl','-q','-v','--ipv6','--noproxy','*','--max-time','5',
                '--resolve','cloudflare-dns.com:443:[2606:4700:4700::1111]',
                'https://cloudflare-dns.com/dns-query?name=.&type=NS',check=False)
            print(diagnostic.stdout.decode(errors='replace'),diagnostic.stderr.decode(errors='replace'),flush=True)
        assert result.returncode==0,result.stderr.decode(errors='replace')[-2000:]
    def state(container):
        return {'pid':command('docker','inspect','-f','{{.State.Pid}}',container),
                'keys':command('docker','exec',container,'sha256sum','/opt/amnezia/xray/server.json','/opt/amnezia/xray/lab.key'),
                'routes':command('docker','exec',container,'cat','/proc/net/route'),
                'dns':command('docker','exec',container,'cat','/etc/resolv.conf')}
    def default_route(enabled):
        command('ip','-6','route','add' if enabled else 'del','default','via','2001:db8:99::1','dev','uplink0')
    try:
        for image in (args.tool_image,args.proxy_image):run('docker','image','inspect',image)
        run('docker','run','-d','--network','none','--privileged','--name',fixture,'--label','amnezia.test-environment=disposable',
            '-e','DOCKER_TLS_CERTDIR=',args.tool_image,'--host=unix:///var/run/docker.sock','--feature','containerd-snapshotter=true',
            '--label','amnezia.test-environment=disposable')
        assert run('docker','inspect','-f','{{.HostConfig.NetworkMode}}',fixture).stdout.strip()==b'none'
        deadline=time.monotonic()+60
        while inside('docker','info',check=False).returncode:
            assert time.monotonic()<deadline,'private daemon startup timeout';time.sleep(.2)
        save=subprocess.Popen(['docker','image','save',args.proxy_image],stdout=subprocess.PIPE);children.append(save)
        loaded=subprocess.run(['docker','exec','-i',fixture,'docker','image','load'],stdin=save.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
        save.stdout.close();assert loaded.returncode==0 and save.wait(timeout=30)==0
        command('touch','/run/amnezia-proxy-ipv6-fixture');command('mkdir','-p','/run/sshd');command('ssh-keygen','-A')
        inside('chpasswd',data=b'root:synthetic-probe-fixture\n')
        command('/usr/sbin/sshd','-p','2222','-o','PermitRootLogin=yes','-o','PasswordAuthentication=yes')
        command('ip','netns','add','provider');command('ip','-n','provider','link','set','lo','up')
        command('ip','link','add','uplink0','type','veth','peer','name','origin0','netns','provider')
        for namespace,iface,v4,v6 in ((None,'uplink0','198.51.100.2/24','2001:db8:99::2/64'),('provider','origin0','198.51.100.1/24','2001:db8:99::1/64')):
            prefix=['ip'] if namespace is None else ['ip','-n',namespace]
            command(*prefix,'link','set',iface,'up');command(*prefix,'addr','add',v4,'dev',iface);command(*prefix,'-6','addr','add',v6,'dev',iface,'nodad')
        for ip in ('2606:4700:4700::1111/128','2001:4860:4860::8888/128'):command('ip','-n','provider','-6','addr','add',ip,'dev','lo','nodad')
        if args.tun_runner:
            command('ip','netns','exec','provider','sysctl','-w','net.ipv4.ip_forward=1')
            for protocol in ('tcp','udp'):
                command('ip','netns','exec','provider','iptables','-t','nat','-A','PREROUTING','-p',protocol,'--dport','38443',
                        '-j','DNAT','--to-destination','198.51.100.2:38443')
                command('ip','netns','exec','provider','iptables','-t','nat','-A','POSTROUTING','-p',protocol,'--dport','38443',
                        '-j','SNAT','--to-source','198.51.100.1')
        command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Isolated proxy IPv6 fixture',
                '-addext','subjectAltName=DNS:cloudflare-dns.com,DNS:dns.google,DNS:routing-xray.test',
                '-addext','basicConstraints=critical,CA:TRUE','-keyout','/lab.key','-out','/lab.crt')
        upload(HTTPS.encode(),'/provider.py');upload(ORIGINS.encode(),'/origins.py');upload(CLIENT.encode(),'/proxy-client.py')
        for script in ('/provider.py','/origins.py'):
            process=pipe('ip','netns','exec','provider','python3','-u',script);assert process.stdout.readline().strip()=='READY'
        command('docker','network','create','amnezia-dns-net')
        ca=command('cat','/lab.crt').splitlines()
        for container,kind in (('amnezia-xray','vless'),('amnezia-ssxray','shadowsocks')):
            command('docker','tag',args.proxy_image,container)
            application(container,'create-ipv4')
            networks=json.loads(command('docker','inspect','-f','{{json .NetworkSettings.Networks}}',container))
            assert 'amnezia-ipv6-egress' not in networks,'IPv4-only host unexpectedly enabled IPv6'
            identity=str(uuid.uuid4())
            settings={'decryption':'none','clients':[{'id':identity}]} if kind=='vless' else {'method':'aes-128-gcm','password':'synthetic-proxy-password','network':'tcp,udp'}
            inbound={'listen':'0.0.0.0','port':38443,'protocol':kind,'settings':settings}
            if kind=='vless':inbound['streamSettings']={'network':'tcp','security':'tls','tlsSettings':{'certificates':[{'certificateFile':'/opt/amnezia/xray/lab.crt','keyFile':'/opt/amnezia/xray/lab.key'}]}}
            config={'log':{'loglevel':'warning'},'inbounds':[inbound],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['198.51.100.1/32','2001:db8:99::1/128'],'port':'18081-18082'}]}}]}
            upload(json.dumps(config).encode(),'/server.json')
            startup=(root/'client/server_scripts/xray/start.sh').read_text().replace('$XRAY_SERVER_PORT','38443')
            upload(startup.encode(),'/proxy-start.sh')
            for source,dest in (('/server.json','/opt/amnezia/xray/server.json'),('/lab.crt','/opt/amnezia/xray/lab.crt'),('/lab.key','/opt/amnezia/xray/lab.key'),('/proxy-start.sh','/opt/amnezia/start.sh')):
                command('docker','cp',source,container+':'+dest)
            command('docker','exec',container,'chmod','700','/opt/amnezia/start.sh');command('docker','restart',container)
            server_ip=command('docker','inspect','-f','{{(index .NetworkSettings.Networks "bridge").IPAddress}}',container)
            command('docker','cp',container+':/usr/bin/xray','/xray-client')
            target={'tag':'proxy','protocol':kind}
            if kind=='vless':
                target['settings']={'vnext':[{'address':server_ip,'port':38443,'users':[{'id':identity,'encryption':'none'}]}]}
                target['streamSettings']={'network':'tcp','security':'tls','tlsSettings':{'serverName':'routing-xray.test','disableSystemRoot':True,'certificates':[{'usage':'verify','certificate':ca}]}}
            else:target['settings']={'servers':[{'address':server_ip,'port':38443,'method':'aes-128-gcm','password':'synthetic-proxy-password'}]}
            target.setdefault('streamSettings',{})['sockopt']={'mark':130}
            upload(json.dumps({'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':39080,'protocol':'socks','settings':{'udp':True}}],'outbounds':[target]}).encode(),'/client.json')
            client=pipe('sh','-ec','echo $$ > /run/proxy-client.pid; exec /xray-client run -config /client.json');time.sleep(.3)
            stream=pipe('python3','-u','/proxy-client.py')
            first=stream.stdout.readline()
            assert first,stream.stderr.read()+'\n'+(client.stderr.read() if client.poll() is not None else '')
            initial=json.loads(first);assert initial['ready']
            original=state(container)
            def retained(label):
                stream.stdin.write(label+'\n');stream.stdin.flush();assert stream.stdout.readline().strip()=='SAME_TCP'
            retained('before');default_route(True)
            application(container,'unavailable');retained('untrusted-ca')
            command('docker','cp','/lab.crt',container+':/usr/local/share/ca-certificates/proxy-lab.crt')
            command('docker','exec',container,'update-ca-certificates')
            application(container,'verified');retained('verified')
            application(container,'verified');retained('idempotent')
            current=state(container);assert current==original,'proxy PID, keys, IPv4 routes or DNS changed'
            for action,expected in (('ipv6','IPV6_TCP'),('udp6','IPV6_UDP')):
                stream.stdin.write(action+'\n');stream.stdin.flush();assert stream.stdout.readline().strip()==expected
            if args.tun_runner:
                subnet=json.loads(command('docker','network','inspect','amnezia-ipv6-egress'))[0]['IPAM']['Config'][0]['Subnet']
                # The lab client and Docker server share a host. Real deployed
                # servers do not; keep server-forwarded packets on their underlay.
                command('ip','-6','rule','add','priority','1000','from',subnet,'lookup','main')
                try:
                    client_config=json.loads(command('cat','/client.json'))
                    client_config['log']={'loglevel':'debug'}
                    client_config['inbounds'][0]['port']=39081
                    outbound=client_config['outbounds'][0]['settings']
                    outbound['vnext' if kind=='vless' else 'servers'][0]['address']='198.51.100.1'
                    result=run(str(args.tun_runner.resolve()),fixture,subnet,data=json.dumps(client_config).encode(),timeout=120,check=False)
                    print(result.stdout.decode(errors='replace'),result.stderr.decode(errors='replace'),flush=True)
                    if result.returncode:
                        for parts in (('iptables-save','-c'),('ip','netns','exec','provider','iptables-save','-c'),
                                      ('ip','-6','rule','show'),('cat','/run/proxy-origins.jsonl')):
                            detail=inside(*parts,check=False)
                            print(detail.stdout.decode(errors='replace'),detail.stderr.decode(errors='replace'),flush=True)
                    assert result.returncode==0,f'Linux TUN runner exit {result.returncode}'
                    assert b'LINUX_PROXY_IPV6_TUN_TCP_UDP_PASS' in result.stdout+result.stderr
                finally:command('ip','-6','rule','del','priority','1000','from',subnet,'lookup','main')
                retained('after-linux-tun')
            stream.stdin.close();stream.wait(timeout=10)
            command('sh','-ec','kill "$(cat /run/proxy-client.pid)"')
            client.wait(timeout=10)
            report['protocols'][container]={'kind':kind,'old_tcp_origin_id':initial['origin_id'],'same_proxy_pid':True,'same_keys':True,
                'ipv4_routes_preserved':True,'dns_preserved':True,'untrusted_ca_rejected':True,'idempotent':True,'new_ipv6_tcp':True,'new_ipv6_udp':True,
                'linux_tun_tcp_udp':bool(args.tun_runner)}
            command('docker','rm','-f',container)
            if container=='amnezia-xray':
                application(container,'create-ipv6')
                networks=json.loads(command('docker','inspect','-f','{{json .NetworkSettings.Networks}}',container))
                assert 'amnezia-ipv6-egress' in networks,'new proxy install missed automatic IPv6 bridge'
                report['protocols'][container]['new_install_ipv6_attached']=True
                command('docker','rm','-f',container)
            default_route(False)
        observations=[json.loads(line) for line in command('cat','/run/provider-observations.jsonl').splitlines()]
        assert observations and all(':' in item['source'] for item in observations)
        report['authenticated_ipv6_observations']=observations
        report['origin_observations']=[json.loads(line) for line in command('cat','/run/proxy-origins.jsonl').splitlines()]
        report['proxy_image']=run('docker','image','inspect','-f','{{.Id}}',args.proxy_image).stdout.decode().strip()
        report['result']='PASS'
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        run('docker','rm','-f',fixture,check=False)
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
