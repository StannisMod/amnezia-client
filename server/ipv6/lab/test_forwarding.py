"""Real kernel IPv6 routing/NAT test in a disposable, isolated namespace."""
import json
import subprocess
import sys

def run(*args):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    if result.returncode:
        raise RuntimeError(f'{args!r}: {result.stdout}')
    return result.stdout.strip()

run('ip','link','set','lo','up')
for name in ('client','origin'):
    run('ip','netns','add',name)
    run('ip','-n',name,'link','set','lo','up')
for host,peer,namespace,local,remote in (
    ('wg0','client0','client','fd77::1/64','fd77::2/64'),
    ('eth0','origin0','origin','fd88::2/64','fd88::1/64'),
):
    run('ip','link','add',host,'type','veth','peer','name',peer)
    run('ip','link','set',peer,'netns',namespace)
    run('ip','link','set',host,'up')
    run('ip','-n',namespace,'link','set',peer,'up')
    run('ip','-6','addr','add',local,'dev',host,'nodad')
    run('ip','-n',namespace,'-6','addr','add',remote,'dev',peer,'nodad')
run('ip','-6','route','add','default','via','fd88::1','dev','eth0')
run('ip','-n','client','-6','route','add','default','via','fd77::1','dev','client0')
run('ip6tables','-P','FORWARD','DROP')
run('ip6tables','-A','FORWARD','-s','fd66::/64','-j','DROP')
# Exercise the same prepended startup resource used by the real application.
# The maintenance branch must return without executing wg-quick down/up.
flag='--amnezia-prepare-ipv6-forwarding'
command=['bash','/app/wireguard-start.sh',flag,'wg0']
unchanged=run('ip6tables','-S')+run('ip6tables','-t','nat','-S')
for bad in ([flag], [flag,'invalid'], [flag,'awg0'], [flag,'wg0','extra']):
 result=subprocess.run(['bash','/app/wireguard-start.sh',*bad],capture_output=True,timeout=10)
 assert result.returncode!=0, 'invalid maintenance request accepted'
 assert unchanged==run('ip6tables','-S')+run('ip6tables','-t','nat','-S'), 'invalid request changed rules'
# With no tunnel IPv6, startup may remain IPv4-only, but migration must fail.
run('ip','-6','addr','del','fd77::1/64','dev','wg0')
missing=subprocess.run(command,capture_output=True,text=True,timeout=10)
assert missing.returncode!=0 and 'no-tunnel-address' in missing.stderr
run('sh','-ec','. /app/enable_ipv6_forwarding.sh; amnezia_enable_ipv6 wg0')
assert unchanged==run('ip6tables','-S')+run('ip6tables','-t','nat','-S')
run('ip','-6','addr','add','fd77::1/64','dev','wg0','nodad')
run('ip','-6','route','del','default','via','fd88::1','dev','eth0')
missing_route=subprocess.run(command,capture_output=True,text=True,timeout=10)
assert missing_route.returncode!=0 and 'no-egress-route' in missing_route.stderr
assert unchanged==run('ip6tables','-S')+run('ip6tables','-t','nat','-S')
run('ip','-6','route','add','default','via','fd88::1','dev','eth0')
# An original IPv4 TCP connection must survive live IPv6 preparation.
for namespace,device,address in ((None,'wg0','10.77.0.1/24'),('client','client0','10.77.0.2/24'),
                                  (None,'eth0','10.88.0.2/24'),('origin','origin0','10.88.0.1/24')):
 prefix=['ip'] if namespace is None else ['ip','-n',namespace]
 run(*prefix,'addr','add',address,'dev',device)
run('sysctl','-w','net.ipv4.ip_forward=1')
run('ip','-n','client','route','add','default','via','10.77.0.1')
run('ip','-n','origin','route','add','10.77.0.0/24','via','10.88.0.2')
server4="""import socket
s=socket.socket();s.bind(('10.88.0.1',18082));s.listen();print('READY',flush=True)
c,peer=s.accept()
for _ in range(2):
 data=c.recv(4096);assert data;c.sendall(data)
c.close();s.close()
"""
origin4=subprocess.Popen(['ip','netns','exec','origin',sys.executable,'-c',server4],stdout=subprocess.PIPE,text=True)
assert origin4.stdout.readline().strip()=='READY'
client4="""import socket,sys
s=socket.create_connection(('10.88.0.1',18082),timeout=5)
identity=(s.getsockname(),s.getpeername())
for phase in ('before','after'):
 data=phase.encode();s.sendall(data);assert s.recv(4096)==data
 if phase=='before':
  print('READY',flush=True);assert sys.stdin.readline().strip()=='continue'
assert identity==(s.getsockname(),s.getpeername());print('SAME_TCP',flush=True)
s.close()
"""
flow4=subprocess.Popen(['ip','netns','exec','client',sys.executable,'-c',client4],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
assert flow4.stdout.readline().strip()=='READY'
ipv4_rules=run('iptables','-S')+run('iptables','-t','nat','-S')
ipv4_routes=run('ip','-4','route','show','table','all')
run(*command)
first=run('ip6tables','-S')+run('ip6tables','-t','nat','-S')
run(*command)
assert first==run('ip6tables','-S')+run('ip6tables','-t','nat','-S'), 'startup duplicated firewall rules'
for kind in ('awg','awg-legacy'):
 run('bash','/app/'+kind+'-start.sh',flag,'wg0')
 assert first==run('ip6tables','-S')+run('ip6tables','-t','nat','-S'), 'alternate startup duplicated rules'
assert ipv4_rules==run('iptables','-S')+run('iptables','-t','nat','-S'), 'IPv6 preparation changed IPv4 firewall'
assert ipv4_routes==run('ip','-4','route','show','table','all'), 'IPv6 preparation changed IPv4 routes'
flow4.stdin.write('continue\n');flow4.stdin.flush()
assert flow4.stdout.readline().strip()=='SAME_TCP'
assert flow4.wait(timeout=5)==0 and origin4.wait(timeout=5)==0
run('ip6tables','-C','FORWARD','-s','fd66::/64','-j','DROP')
server='''import socket,json
s=socket.socket(socket.AF_INET6);s.bind(('fd88::1',18081));s.listen();print('READY',flush=True)
c,peer=s.accept();data=c.recv(4096);c.sendall(data);c.close();s.close();print(json.dumps({'remote':peer[0],'bytes':len(data)}),flush=True)
'''
process=subprocess.Popen(['ip','netns','exec','origin',sys.executable,'-c',server],stdout=subprocess.PIPE,text=True)
assert process.stdout.readline().strip()=='READY', 'origin did not start'
client='''import socket
s=socket.socket(socket.AF_INET6);s.settimeout(5);s.connect(('fd88::1',18081));s.sendall(b'ipv6-egress-proof');assert s.recv(4096)==b'ipv6-egress-proof';s.close()
'''
run('ip','netns','exec','client',sys.executable,'-c',client)
observed=json.loads(process.stdout.readline())
assert process.wait(timeout=5)==0
assert observed=={'remote':'fd88::2','bytes':17}, observed
print(json.dumps({'status':'PASS_KERNEL_IPV6_FORWARDING','observed':observed,'repeat_startup':'PASS','foreign_rule_retained':'PASS','live_ipv4_tcp':'PASS','startup_maintenance_all_protocols':'PASS','missing_ipv6_rejected':'PASS'}),flush=True)
