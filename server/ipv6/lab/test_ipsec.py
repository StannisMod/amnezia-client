"""Real Libreswan/strongSwan dual-stack IKEv2, isolated Docker namespaces only."""
import ipaddress
import json
import os
import select
from pathlib import Path
import subprocess
import time


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=kwargs.pop('timeout', 30), **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args!r}: {result.stdout}')
    return result.stdout


assert Path('/.dockerenv').exists()
assert {r['ifname'] for r in json.loads(run('ip', '-j', 'link'))} == {'lo'}, 'requires isolated --network none'
source = Path('/src/client/server_scripts/ipsec/configure_container.sh')
root = Path('/opt/ipsec-fixture')
root.mkdir(parents=True, exist_ok=True)
names = ('ike-client', 'ike-origin')
processes, logs = [], []


def spawn(arguments, log):
    stream = (root / log).open('w')
    logs.append(stream)
    process = subprocess.Popen(arguments, stdout=stream, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def wait_file(path):
    deadline = time.monotonic() + 10
    while not Path(path).exists():
        assert time.monotonic() < deadline, f'{path} did not appear'
        assert all(p.poll() is None for p in processes), 'VPN daemon exited'
        time.sleep(.1)


try:
    run('ip', 'link', 'set', 'lo', 'up')
    for name in names:
        run('ip', 'netns', 'add', name)
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
    for local, peer, ns, address, remote in (
        ('server0', 'client0', names[0], '198.51.100.1/24', '198.51.100.2/24'),
        ('egress0', 'origin0', names[1], '192.0.2.2/24', '192.0.2.1/24'),
    ):
        run('ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', ns)
        run('ip', 'addr', 'add', address, 'dev', local)
        run('ip', 'link', 'set', local, 'up')
        run('ip', '-n', ns, 'addr', 'add', remote, 'dev', peer)
        run('ip', '-n', ns, 'link', 'set', peer, 'up')
    run('ip', '-6', 'addr', 'add', 'fd88::2/64', 'dev', 'egress0', 'nodad')
    run('ip', '-n', names[1], '-6', 'addr', 'add', 'fd88::1/64', 'dev', 'origin0', 'nodad')
    run('ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    run('ip', '-6', 'route', 'add', 'default', 'via', 'fd88::1')
    run('ip', '-n', names[0], 'route', 'add', 'default', 'via', '198.51.100.1')
    run('ip', '-n', names[1], 'route', 'add', 'default', 'via', '192.0.2.2')
    run('ip', '-n', names[1], '-6', 'route', 'add', 'default', 'via', 'fd88::2')
    run('sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    for tool in ('iptables', 'ip6tables'):
        # No unencrypted client-origin packet can satisfy the acceptance test.
        run(tool, '-A', 'FORWARD', '-i', 'server0', '-m', 'policy', '--dir', 'in', '--pol', 'ipsec', '-j', 'ACCEPT')
        run(tool, '-A', 'FORWARD', '-i', 'server0', '-j', 'DROP')
        run(tool, '-A', 'FORWARD', '-o', 'server0', '-m', 'policy', '--dir', 'out', '--pol', 'ipsec', '-j', 'ACCEPT')
        run(tool, '-A', 'FORWARD', '-o', 'server0', '-j', 'DROP')
    for tool, prefix in (('iptables', '192.168.43.0/24'), ('ip6tables', 'fd6e:a81b:704f:1201::/64')):
        run(tool, '-t', 'nat', '-A', 'POSTROUTING', '-s', prefix, '-o', 'egress0', '-j', 'MASQUERADE')

    db = Path('/etc/ipsec.d')
    db.mkdir(exist_ok=True)
    run('certutil', '-N', '--empty-password', '-d', 'sql:' + str(db))
    noise = root / 'noise'
    noise.write_bytes(os.urandom(1024))
    common = ['-k', 'rsa', '-g', '2048', '-v', '1', '-d', 'sql:' + str(db), '-z', str(noise)]
    run('certutil', '-S', '-x', '-n', 'fixture-ca', '-s', 'CN=Fixture CA', '-m', '1', '-t', 'CT,,', '-2', *common, input='y\n\nN\n')
    for nickname, subject, serial, usage in (('198.51.100.1', '198.51.100.1', '2', 'serverAuth'),
                                            ('fixture-client', 'Fixture Client', '3', 'clientAuth')):
        run('certutil', '-S', '-c', 'fixture-ca', '-n', nickname, '-s', 'CN=' + subject,
            '-m', serial, '-t', ',,', '--keyUsage', 'digitalSignature,keyEncipherment',
            '--extKeyUsage', usage, '--extSAN', 'ip:198.51.100.1' if usage == 'serverAuth' else 'dns:fixture-client', *common)
    for folder in ('x509ca', 'x509', 'private'):
        Path('/etc/swanctl', folder).mkdir(parents=True, exist_ok=True)
    Path('/etc/swanctl/x509ca/ca.pem').write_text(run('certutil', '-L', '-d', 'sql:' + str(db), '-n', 'fixture-ca', '-a'))
    Path('/etc/swanctl/x509/client.pem').write_text(run('certutil', '-L', '-d', 'sql:' + str(db), '-n', 'fixture-client', '-a'))
    run('pk12util', '-o', str(root / 'client.p12'), '-n', 'fixture-client', '-d', 'sql:' + str(db), '-W', 'fixture-password', '-K', '')
    run('openssl', 'pkcs12', '-legacy', '-in', str(root / 'client.p12'), '-passin', 'pass:fixture-password',
        '-nodes', '-nocerts', '-out', '/etc/swanctl/private/client.pem')

    body = source.read_text().split('cat > /etc/ipsec.d/ikev2.conf <<EOF\n', 1)[1].split('\nEOF', 1)[0]
    for variable, value in {'SERVER_IP_ADDRESS': '198.51.100.1', 'PRIMARY_SERVER_DNS': '1.1.1.1', 'SECONDARY_SERVER_DNS': '8.8.8.8'}.items():
        body = body.replace('$' + variable, value)
    # The outer endpoint is fixed in the lab; only add the proposed dual-stack
    # selectors/pool to the exact production IKEv2 policy.
    body = body.replace('left=%defaultroute', 'left=198.51.100.1')
    body = body.replace('leftsubnet=0.0.0.0/0', 'leftsubnet=0.0.0.0/0,::/0')
    body = body.replace('rightaddresspool=192.168.43.10-192.168.43.250',
                        'rightaddresspool=192.168.43.10-192.168.43.250,fd6e:a81b:704f:1201::1000-fd6e:a81b:704f:1201::1fff')
    Path('/etc/ipsec.conf').write_text('version 2.0\nconfig setup\n  uniqueids=no\n\n' + body + '\n')
    Path('/etc/ipsec.secrets').touch()
    Path('/etc/swanctl/swanctl.conf').write_text('''connections {
  fixture {
    version = 2
    local_addrs = 198.51.100.2
    remote_addrs = 198.51.100.1
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
    spawn(['/usr/local/libexec/ipsec/pluto', '--nofork', '--config', '/etc/ipsec.conf'], 'pluto.log')
    wait_file('/run/pluto/pluto.ctl')
    loaded = run('/usr/local/sbin/ipsec', 'addconn', '--autoall', '--config', '/etc/ipsec.conf')
    print(loaded, flush=True)
    assert 'failed to add' not in loaded, 'Libreswan rejected the actual connection'
    spawn(['ip', 'netns', 'exec', names[0], '/usr/lib/strongswan/charon'], 'charon.log')
    wait_file('/run/charon.vici')
    print(run('ip', 'netns', 'exec', names[0], 'swanctl', '--load-all'), flush=True)
    print(run('ip', 'netns', 'exec', names[0], 'swanctl', '--initiate', '--child', 'tunnel', '--timeout', '15'), flush=True)
    addresses = json.loads(run('ip', '-n', names[0], '-j', 'addr'))
    assigned = [a['local'] for row in addresses for a in row['addr_info']]
    assert any(ipaddress.ip_address(a) in ipaddress.ip_network('192.168.43.0/24') for a in assigned if ':' not in a)
    assert any(ipaddress.ip_address(a) in ipaddress.ip_network('fd6e:a81b:704f:1201::/64') for a in assigned if ':' in a)
    print('PASS: independent IKEv2 peer negotiated and installed both virtual address families', flush=True)
    echo = '''import socket,threading
from pathlib import Path
def tcp(c,peer):
 try:
  c.sendall((peer+'\\n').encode())
  while c.recv(4096):c.sendall((peer+'\\n').encode())
 except OSError:pass
 finally:c.close()
def accept(s):
 while True:
  c,a=s.accept();threading.Thread(target=tcp,args=(c,a[0]),daemon=True).start()
def udp(s):
 while True:
  data,a=s.recvfrom(4096);s.sendto(a[0].encode(),a)
for family,address in ((socket.AF_INET,'192.0.2.1'),(socket.AF_INET6,'fd88::1')):
 for kind,worker in ((socket.SOCK_STREAM,accept),(socket.SOCK_DGRAM,udp)):
  s=socket.socket(family,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  s.bind((address,18081))
  if kind==socket.SOCK_STREAM:s.listen()
  threading.Thread(target=worker,args=(s,),daemon=True).start()
Path('/opt/ipsec-fixture/origin.ready').touch()
threading.Event().wait()
'''
    spawn(['ip', 'netns', 'exec', names[1], 'python3', '-u', '-c', echo], 'origin.log')
    wait_file(root / 'origin.ready')
    probe = '''import socket,sys
def read(s):
 data=b''
 while not data.endswith(b'\\n'):
  chunk=s.recv(64);assert chunk,'TCP closed';data+=chunk
 return data.strip().decode()
targets=[(socket.AF_INET,'192.0.2.1','192.0.2.2'),(socket.AF_INET6,'fd88::1','fd88::2')]
sockets=[]
def udp():
 for family,target,peer in targets:
  with socket.socket(family,socket.SOCK_DGRAM) as s:
   s.settimeout(3);s.sendto(b'PATH',(target,18081));assert s.recv(64).decode()==peer
for family,target,peer in targets:
 print('Opening TCP to '+target,file=sys.stderr,flush=True)
 s=socket.create_connection((target,18081),3);assert read(s)==peer;sockets.append((s,peer))
udp()
print('TCP_UDP_READY',flush=True)
assert sys.stdin.readline().strip()=='blackout'
for s,peer in sockets:s.sendall(b'during-blackout');s.settimeout(.5)
for s,peer in sockets:
 try:
  s.recv(64);raise AssertionError('outer-path blackhole did not block TCP')
 except socket.timeout:pass
print('BLACKHOLE_CONFIRMED',flush=True)
assert sys.stdin.readline().strip()=='resume'
for s,peer in sockets:
 s.settimeout(12);assert read(s)==peer
 s.sendall(b'same-original-socket');assert read(s)==peer
udp()
print('ORIGINAL_DUAL_TCP_RETAINED',flush=True)
'''
    original = subprocess.Popen(['ip', 'netns', 'exec', names[0], 'python3', '-u', '-c', probe],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    processes.append(original)

    def expect(message, timeout):
        assert select.select([original.stdout], [], [], timeout)[0], f'waiting for {message}'
        assert original.stdout.readline().strip() == message, message

    expect('TCP_UDP_READY', 10)
    print('PASS: IPv4/IPv6 TCP+UDP reach separate origin through XFRM-only forwarding and NAT', flush=True)
    drops = [('iptables', '-i', 'server0', '-p', 'udp', '--dport', '4500', '-j', 'DROP'),
             ('iptables', '-i', 'server0', '-p', 'esp', '-j', 'DROP')]
    for tool, *rule in drops:
        run(tool, '-I', 'INPUT', '1', *rule)
    original.stdin.write('blackout\n'); original.stdin.flush()
    expect('BLACKHOLE_CONFIRMED', 5)
    time.sleep(2)
    for tool, *rule in drops:
        run(tool, '-D', 'INPUT', *rule)
    original.stdin.write('resume\n'); original.stdin.flush()
    expect('ORIGINAL_DUAL_TCP_RETAINED', 15)
    assert original.wait(timeout=5) == 0
    print('PASS: original IPv4 and IPv6 TCP sockets survive outer UDP/ESP blackhole without reconnecting', flush=True)
except Exception:
    for prefix in ([], ['ip', 'netns', 'exec', names[0]]):
        for command in (['ip', '-4', 'route', 'show', 'table', 'all'],
                        ['ip', '-6', 'route', 'show', 'table', 'all'],
                        ['ip', '-s', 'xfrm', 'policy'], ['iptables', '-nvL', 'FORWARD'], ['ip6tables', '-nvL', 'FORWARD'],
                        ['iptables', '-t', 'nat', '-nvL', 'POSTROUTING'],
                        ['sysctl', 'net.ipv4.conf.all.rp_filter']):
            diagnostic = subprocess.run(prefix + command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(prefix + command, diagnostic.stdout, flush=True)
    for log in ('pluto.log', 'charon.log'):
        if (root / log).exists():
            print(log, (root / log).read_text()[-24000:], flush=True)
    raise
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in reversed(processes):
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    for log in logs:
        log.close()
    for name in names:
        subprocess.run(['ip', 'netns', 'del', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
