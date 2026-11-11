"""Real kernel IPv6 routing/NAT test in a disposable, isolated namespace."""
import json
import subprocess
import sys

def run(*args):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
command=['sh','-ec','. /app/enable_ipv6_forwarding.sh; amnezia_enable_ipv6 wg0']
run(*command)
first=run('ip6tables','-S')+run('ip6tables','-t','nat','-S')
run(*command)
assert first==run('ip6tables','-S')+run('ip6tables','-t','nat','-S'), 'startup duplicated firewall rules'
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
print(json.dumps({'status':'PASS_KERNEL_IPV6_FORWARDING','observed':observed,'repeat_startup':'PASS','foreign_rule_retained':'PASS'}),flush=True)
