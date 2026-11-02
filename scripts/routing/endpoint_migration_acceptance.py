#!/usr/bin/env python3
"""Real endpoint DNS/IP migration through the installed service (Linux CI).

All DNS and peer traffic lives in a disposable network namespace. No public
DNS or user server is contacted, and the host resolver is never rewritten.
"""
import json
import os
from pathlib import Path
import queue
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid


def command(*args):
    return subprocess.run(list(map(str, args)), check=True, timeout=20, stdout=subprocess.DEVNULL)


def node(state_file, fixture_file, upstream_port):
    """Controlled DNS and two UDP front doors for the same AWG peer/keys."""
    state_file = Path(state_file)
    dns_sockets, relays, clients = [], {}, {}
    for ip in ('1.1.1.1', '8.8.8.8'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((ip, 53)); dns_sockets.append(s)
    for ip in ('192.0.2.10', '192.0.2.20'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((ip, int(upstream_port))); relays[s] = ip
    while True:
        for s in select.select(dns_sockets + list(relays), [], [], 1)[0]:
            data, sender = s.recvfrom(65535)
            state = json.loads(state_file.read_text())
            if s in dns_sockets:
                # Leave time to prove unrelated native traffic stays blocked
                # during bootstrap, while the service's private socket works.
                time.sleep(.25)
                answer = bytearray(data)
                answer[2:4] = b'\x81\x80'
                if data[-4:-2] == b'\0\1':
                    answer[6:8] = b'\0\1'
                    answer += b'\xc0\x0c\0\1\0\1\0\0\0\0\0\4' + socket.inet_aton(state['address'])
                s.sendto(answer, sender)
            elif sender == ('127.0.0.1', int(upstream_port)):
                if s in clients and relays[s] == state['address']: s.sendto(data, clients[s])
            elif relays[s] == state['address']:
                clients[s] = sender
                s.sendto(data, ('127.0.0.1', int(upstream_port)))


def run(qt_probe, peer_binary, temporary):
    from run_linux_acceptance import resolve, tcp
    namespace = 'amn-endpoint-' + uuid.uuid4().hex[:8]
    host_if = 'aep' + uuid.uuid4().hex[:8]
    root = Path(temporary) / 'endpoint-migration'; root.mkdir()
    driver = Path(qt_probe).with_name('routing-endpoint-probe')
    assert driver.is_file(), 'production endpoint-session probe missing'
    peer = dns = process = None
    events = queue.Queue()
    state = root / 'dns.json'
    def publish(address):
        staging = state.with_suffix('.tmp')
        staging.write_text(json.dumps({'address': address}))
        staging.replace(state)
    publish('192.0.2.10')
    def toggle(enabled): command(qt_probe, 'on' if enabled else 'off')
    def stop():
        nonlocal process
        if process is None: return
        (root / 'stop').touch()
        process.wait(timeout=15)
        assert process.returncode == 0, 'endpoint session failed to stop with service acknowledgement'
        process = None
    def wait_connected(address, timeout=30):
        end = time.monotonic() + timeout
        resolving = False
        while time.monotonic() < end:
            row = events.get(timeout=max(.1, end - time.monotonic()))
            assert row.get('event') != 'failed', 'production recovery failed: ' + json.dumps(row)
            if row.get('event') == 'phase' and row.get('phase') == 1:
                resolving = True
                if strict:
                    time.sleep(.05)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(.15)
                        try:
                            s.sendto(b'proof', ('192.0.2.10', 18082)); s.recv(100)
                        except OSError: pass
                        else: raise AssertionError('native traffic escaped during strict endpoint bootstrap')
            if row.get('event') == 'connected' and row['address'] == address:
                assert resolving, 'recovery reused a pinned numeric endpoint instead of querying DNS'
                return
        raise AssertionError('endpoint recovery timed out')
    try:
        toggle(False)
        command('ip', 'netns', 'add', namespace)
        command('ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', namespace)
        command('ip', 'addr', 'add', '10.203.0.1/30', 'dev', host_if)
        command('ip', 'link', 'set', host_if, 'up')
        def ns(*args): command('ip', 'netns', 'exec', namespace, *args)
        ns('ip', 'link', 'set', 'lo', 'up'); ns('ip', 'link', 'set', 'eth0', 'up')
        ns('ip', 'addr', 'add', '10.203.0.2/30', 'dev', 'eth0')
        ns('ip', 'route', 'add', 'default', 'via', '10.203.0.1')
        for ip in ('1.1.1.1', '8.8.8.8', '192.0.2.10', '192.0.2.20'):
            ns('ip', 'addr', 'add', ip + '/32', 'dev', 'eth0')
            command('ip', 'route', 'add', ip + '/32', 'via', '10.203.0.2', 'dev', host_if)
        fixture = root / 'peer.json'
        peer = subprocess.Popen(['ip', 'netns', 'exec', namespace, str(peer_binary), '--shared-ip', '192.0.2.10',
                                 '--bind-ip', '127.0.0.1', '--config', str(fixture)], stdout=subprocess.PIPE, text=True)
        assert select.select([peer.stdout], [], [], 15)[0] and peer.stdout.readline().startswith('READY')
        profile = json.loads(fixture.read_text())
        port = profile['awg_config_data']['port']
        profile['awg_config_data']['hostName'] = 'endpoint.test'
        profile['sing_box_routing'] = {'version': 1, 'default': 'vpn', 'rules': []}
        profile['killSwitchOption'] = 'true'
        profile_file = root / 'profile.json'; profile_file.write_text(json.dumps(profile))
        original = profile_file.read_bytes()
        dns = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable, __file__, '--node', str(state), str(fixture), str(port)])
        time.sleep(.2)
        # The same peer process and exact profile keys span both migrations.
        for strict in (False, True):
            publish('192.0.2.10')
            toggle(strict)
            (root / 'stop').unlink(missing_ok=True)
            events = queue.Queue()
            process = subprocess.Popen([str(driver), str(profile_file), str(root / 'stop')], stdout=subprocess.PIPE, text=True)
            def read_events(source, destination):
                for line in source: destination.put(json.loads(line))
                destination.put({'event': 'failed', 'reason': 'probe exited'})
            threading.Thread(target=read_events, args=(process.stdout, events), daemon=True).start()
            wait_connected('192.0.2.10')
            assert tcp(resolve('vpn.test')) == 'VPN'
            publish('192.0.2.20')
            # Outbound traffic/keepalives and no inbound progress must trigger
            # the real session watchdog; there is no explicit reconnect call.
            traffic_stop = threading.Event()
            def send_traffic():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    while not traffic_stop.wait(.1):
                        try: s.sendto(b'proof', ('192.0.2.10', 18082))
                        except OSError: pass
            traffic = threading.Thread(target=send_traffic, daemon=True); traffic.start()
            try: wait_connected('192.0.2.20')
            finally: traffic_stop.set(); traffic.join(timeout=2)
            assert tcp(resolve('vpn.test')) == 'VPN'
            assert profile_file.read_bytes() == original, 'keys or saved domain were rewritten'
            stop()
            rules = subprocess.check_output(['iptables-save'], text=True, timeout=10)
            assert 'amnezia-endpoint-dns' not in rules, 'bootstrap firewall exception survived lookup/stop'
            if strict:
                # An ordinary DNS socket is still blocked after the endpoint
                # bootstrap exception has been removed.
                query = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + b'\x08endpoint\x04test\0\0\1\0\1'
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(.5)
                    try:
                        s.sendto(query, ('1.1.1.1', 53)); s.recv(4096)
                    except OSError: pass
                    else: raise AssertionError('strict switch leaked DNS through a stale bootstrap exception')
        return {'dns_ip_migration': 'PASS', 'strict_on_and_off': 'PASS', 'same_peer_and_keys': 'PASS', 'automatic_watchdog': 'PASS'}
    finally:
        if process is not None:
            try: stop()
            except Exception: process.kill(); process.wait(timeout=5)
        toggle(False)
        for child in (dns, peer):
            if child is not None: child.terminate(); child.wait(timeout=5)
        subprocess.run(['ip', 'link', 'del', host_if], check=False, timeout=10)
        subprocess.run(['ip', 'netns', 'del', namespace], check=False, timeout=10)


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--node':
        node(*sys.argv[2:])
    else: raise SystemExit(2)
