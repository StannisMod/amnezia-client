#!/usr/bin/env python3
"""Owned Docker fixture for the production Android OpenVpnService acceptance.

No Docker socket or host network: share only the owned emulator's otherwise
empty network namespace. Test PKI and fixture JSON are removed on normal stop.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policies', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--case', choices=('full','include','exclude','stale-full'), help='focused local diagnosis; default runs all applicable cases')
    args = parser.parse_args()
    mode = os.environ.get('AMNEZIA_ANDROID_OPENVPN_FIXTURE')
    assert mode in ('owned-container', 'github-hosted')
    if mode == 'owned-container': assert Path('/.dockerenv').exists()
    else: assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
    links = json.loads(subprocess.check_output(['ip', '-d', '-j', 'link'], text=True))
    assert 'tun-ovpn3test' not in {row['ifname'] for row in links}, 'refusing an existing interface'
    if mode == 'owned-container':
        assert {row['ifname'] for row in links} <= {'lo', 'stability6'}, 'requires the owned emulator network with no outside interfaces'
        assert all(row['ifname']=='lo' or row.get('linkinfo',{}).get('info_kind')=='dummy' for row in links)
    assert not args.output.exists(), 'refusing to overwrite another fixture'
    policies = json.loads(args.policies.read_text())
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    addresses, listeners = [], []
    server = None
    pool = ipaddress.ip_network('fd6e:a81b:704f:1101::/64')
    targets = ('fd99::4','fd99::5','2001:db8:42::4','64:ff9b::c000:201')
    with tempfile.TemporaryDirectory(prefix='amnezia-android-openvpn-') as tmp:
        root = Path(tmp)
        def run(*argv):
            subprocess.run(argv, cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        try:
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Local Android OpenVPN CA',
                '-keyout', 'ca.key', '-out', 'ca.crt')
            for name, usage in (('server', 'serverAuth'), ('client', 'clientAuth')):
                run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+name,
                    '-keyout', name+'.key', '-out', name+'.csr')
                (root/(name+'.ext')).write_text('keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n')
                run('openssl', 'x509', '-req', '-in', name+'.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                    '-CAcreateserial', '-days', '1', '-extfile', name+'.ext', '-out', name+'.crt')
            for address in (target+'/128' for target in targets):
                run('ip', '-6', 'addr', 'add', address, 'dev', 'lo', 'nodad')
                addresses.append(address)
            (root/'server.conf').write_text('''local 127.0.0.1
port 21943
proto udp
dev tun-ovpn3test
topology subnet
server 10.76.0.0 255.255.255.0
ca ca.crt
cert server.crt
key server.key
dh none
data-ciphers AES-256-GCM:AES-128-GCM
keepalive 10 60
persist-key
persist-tun
verb 3
''' + ('server-ipv6 '+str(pool)+'\n' if args.ipv6 else ''))
            log = (root/'server.log').open('w')
            server = subprocess.Popen(['openvpn', '--cd', str(root), '--config', 'server.conf'], stdout=log, stderr=subprocess.STDOUT)
            until = time.monotonic()+10
            while 'Initialization Sequence Completed' not in (root/'server.log').read_text():
                assert server.poll() is None and time.monotonic()<until, (root/'server.log').read_text()
                time.sleep(.05)

            def echo(connection):
                try:
                    while True:
                        data=connection.recv(4096)
                        if not data: return
                        connection.sendall(data)
                finally: connection.close()
            def tcp_loop(listener, ipv6):
                try:
                    while not stop.is_set():
                        connection, peer = listener.accept()
                        if not ipv6:
                            threading.Thread(target=echo, args=(connection,), daemon=True).start()
                            continue
                        tag = 'VPN' if ipaddress.ip_address(peer[0]) in pool else 'NATIVE'
                        print('ORIGIN_TCP', listener.getsockname()[0], peer[0], tag, flush=True)
                        with connection: connection.sendall((tag+'\n').encode())
                except OSError:
                    if not stop.is_set(): raise
            def udp_loop(listener):
                try:
                    while not stop.is_set():
                        data, peer = listener.recvfrom(2048)
                        tag = 'VPN' if ipaddress.ip_address(peer[0]) in pool else 'NATIVE'
                        print('ORIGIN_UDP', listener.getsockname()[0], peer[0], tag, flush=True)
                        listener.sendto(tag.encode(), peer)
                except OSError:
                    if not stop.is_set(): raise
            endpoints=[(socket.AF_INET,'10.76.0.1',18080)]
            endpoints += [(socket.AF_INET6,target,21944) for target in targets]
            for family, address, port in endpoints:
                listener=socket.socket(family)
                listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                listener.bind((address,port));listener.listen();listeners.append(listener)
                threading.Thread(target=tcp_loop,args=(listener,family==socket.AF_INET6),daemon=True).start()
                if family==socket.AF_INET6:
                    datagram=socket.socket(family,socket.SOCK_DGRAM);datagram.bind((address,port));listeners.append(datagram)
                    threading.Thread(target=udp_loop,args=(datagram,),daemon=True).start()
            credentials=''.join('\n<'+tag+'>\n'+(root/name).read_text()+'</'+tag+'>\n'
                                for tag,name in (('ca','ca.crt'),('cert','client.crt'),('key','client.key')))
            cases=[]
            modes=[('full',0),('include',1),('exclude',2)]
            if not args.ipv6: modes.append(('stale-full',0))
            for mode, split in modes:
                if args.case and args.case!=mode: continue
                content=policies['full' if mode=='stale-full' else mode if args.ipv6 else 'legacy-'+mode]
                content='\n'.join(line for line in content.splitlines()
                                  if not line.startswith(('remote ', 'up ', 'down ', 'script-security ')))
                assert 'ifconfig-ipv6 fd15:' not in content, 'use Qt TUN-builder fixture, not OpenVPN2 policy'
                config={'protocol':'openvpn','hostName':'10.0.2.2','dns1':'1.1.1.1','dns2':'8.8.8.8',
                        'splitTunnelType':split,'splitTunnelSites':['fd99::4/128' if split==2 else 'fd00::/8','192.0.2.0/24']+(['10.76.0.1/32'] if split==1 else []),
                        'openvpn_config_data':{'port':21943,'config':content+'\nremote 10.0.2.2 21943\nproto udp\ndev tun\nremote-cert-tls server\n'+credentials}}
                def captured(address):
                    if split==1: return ipaddress.ip_address(address) in ipaddress.ip_network('fd00::/8')
                    return split==0 or address!='fd99::4'
                expected={address:('VPN' if args.ipv6 else 'BLOCKED') if captured(address) else 'NATIVE'
                          for address in targets}
                cases.append({'name':mode,'config':config,'expected':expected})
            assert cases, 'selected case is not applicable to this server'
            fixture={'protocol':'openvpn','openvpn_config_data':{'port':21943},'server_ipv6':args.ipv6,'openvpn_cases':cases,'ipv6_test_destinations':targets}
            args.output.parent.mkdir(parents=True,exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w',dir=args.output.parent,delete=False) as out:
                staged=Path(out.name)
                try:
                    json.dump(fixture,out);out.flush()
                    os.link(staged,args.output) # Publish a complete private file without overwriting another.
                finally: staged.unlink(missing_ok=True)
            print('ANDROID_OPENVPN_READY', 'dual-stack' if args.ipv6 else 'IPv4-only', flush=True)
            while not stop.wait(.5):
                assert server.poll() is None, (root/'server.log').read_text()
        finally:
            stop.set()
            args.output.unlink(missing_ok=True)
            for listener in listeners: listener.close()
            if server is not None:
                server.terminate()
                try: server.wait(timeout=5)
                except subprocess.TimeoutExpired: server.kill();server.wait()
                log.close()
                print((root/'server.log').read_text()[-16000:],flush=True)
            for address in reversed(addresses): run('ip','-6','addr','del',address,'dev','lo')


if __name__=='__main__':
    main()
