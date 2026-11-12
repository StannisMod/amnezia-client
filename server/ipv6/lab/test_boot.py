"""Actual startup firewall behavior; tunnel and daemon commands use test doubles."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

kind = sys.argv[1]
assert kind in ('wireguard', 'awg', 'awg-legacy')
iface = 'awg0' if kind == 'awg' else 'wg0'

def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f'{args!r}: {result.stderr}')
    return result.stdout

run('ip', 'link', 'set', 'lo', 'up')
for namespace in ('client', 'origin'):
    run('ip', 'netns', 'add', namespace)
    run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
for local, peer, namespace, address, remote in (
    (iface, 'client0', 'client', '10.77.0.1/24', '10.77.0.2/24'),
    ('eth0', 'origin0', 'origin', '10.88.0.2/24', '10.88.0.1/24'),
):
    run('ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', peer)
    run('ip', 'link', 'set', peer, 'netns', namespace)
    run('ip', 'link', 'set', local, 'up')
    run('ip', '-n', namespace, 'link', 'set', peer, 'up')
    run('ip', 'addr', 'add', address, 'dev', local)
    run('ip', '-n', namespace, 'addr', 'add', remote, 'dev', peer)
run('ip', '-6', 'addr', 'add', 'fd77::1/64', 'dev', iface, 'nodad')
assert not run('ip', '-6', 'route', 'show', 'default').strip()
run('sysctl', '-w', 'net.ipv4.ip_forward=1')
run('ip', '-n', 'client', 'route', 'add', 'default', 'via', '10.77.0.1')
run('ip', '-n', 'origin', 'route', 'add', '10.77.0.0/24', 'via', '10.88.0.2')
# Model the original working VPN NAT before opening the retained connection.
run('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.77.0.0/24', '-o', 'eth0', '-j', 'MASQUERADE')
server = '''import socket
s=socket.socket();s.bind(('10.88.0.1',18083));s.listen();print('READY',flush=True)
for count in (2,1):
 c,peer=s.accept()
 for _ in range(count):
  data=c.recv(4096);assert data;c.sendall(data)
 c.close()
s.close()
'''
origin = subprocess.Popen(['ip','netns','exec','origin',sys.executable,'-c',server],stdout=subprocess.PIPE,text=True)
assert origin.stdout.readline().strip() == 'READY'
client = '''import socket,sys
s=socket.create_connection(('10.88.0.1',18083),timeout=5);identity=(s.getsockname(),s.getpeername())
s.sendall(b'before');assert s.recv(4096)==b'before';print('READY',flush=True)
assert sys.stdin.readline().strip()=='continue'
s.sendall(b'after');assert s.recv(4096)==b'after';assert identity==(s.getsockname(),s.getpeername());s.close()
print('SAME_TCP',flush=True)
'''
flow = subprocess.Popen(['ip','netns','exec','client',sys.executable,'-c',client],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
assert flow.stdout.readline().strip() == 'READY'
run('iptables', '-P', 'FORWARD', 'DROP')
v6_before = run('ip6tables', '-S') + run('ip6tables', '-t', 'nat', '-S')
folder = 'wireguard' if kind == 'wireguard' else 'awg'
configuration = Path('/opt/amnezia') / folder / (iface + '.conf')
configuration.parent.mkdir(parents=True, exist_ok=True)
configuration.write_text('# synthetic config consumed only by quick test double\n')
with tempfile.TemporaryDirectory(prefix='boot-command-doubles-') as directory:
    for name in ('wg-quick', 'awg-quick', 'tail', 'python3'):
        path = Path(directory) / name
        path.write_text('#!/bin/sh\nexit 0\n')
        path.chmod(0o700)
    environment = dict(os.environ, PATH=directory+':/usr/sbin:/usr/bin:/sbin:/bin',
                       WIREGUARD_SUBNET_IP='10.77.0.0', AWG_SUBNET_IP='10.77.0.0', WIREGUARD_SUBNET_CIDR='24')
    program = Path('/app/'+kind+'-start.sh').read_text()
    if os.environ.get('AMNEZIA_BOOT_NEGATIVE_CONTROL') == '1':
        program = program.replace("|| echo 'AMNEZIA_IPV6_FORWARDING_STATUS=boot-preparation-failed' >&2", '|| exit 1')
    boot = subprocess.run(['/bin/bash','-s'],input=program,capture_output=True,text=True,env=environment,timeout=15)
    assert boot.returncode == 0, boot.stderr
    assert 'no-egress-route' in boot.stderr and 'boot-preparation-failed' in boot.stderr, boot.stderr
assert v6_before == run('ip6tables', '-S') + run('ip6tables', '-t', 'nat', '-S')
run('iptables', '-C', 'FORWARD', '-i', iface, '-j', 'ACCEPT')
flow.stdin.write('continue\n');flow.stdin.flush()
assert flow.stdout.readline().strip() == 'SAME_TCP'
assert flow.wait(timeout=5) == 0
fresh = "import socket;s=socket.create_connection(('10.88.0.1',18083),timeout=5);s.sendall(b'new');assert s.recv(4096)==b'new';s.close()"
run('ip','netns','exec','client',sys.executable,'-c',fresh)
assert origin.wait(timeout=5) == 0
print('PASS: '+kind+' missing IPv6 egress preserves startup, original and new IPv4 TCP; IPv6 not reported ready',flush=True)
