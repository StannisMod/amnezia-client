#!/usr/bin/env python3
"""Production WireguardProtocol -> installed Qt service -> native owner.

Only disposable Linux service containers may invoke this. The fixed public
bootstrap addresses and both endpoint front doors live in a private peer netns.
Application sockets are opened once: this test has no reconnect/redial loop.
"""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid


def command(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=30, **kwargs)


def receive(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError('original application stream closed')
        data.extend(chunk)
    return bytes(data)


def run(qt_probe, peer_binary, temporary):
    from run_linux_acceptance import resolve
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('disposable root Linux service wrapper required')
    driver = Path(qt_probe).with_name('routing-wireguard-probe')
    assert driver.is_file(), 'production WireguardProtocol probe missing'
    namespace = 'amn-preserve-' + uuid.uuid4().hex[:8]
    host_if = 'apr' + uuid.uuid4().hex[:8]
    root = Path(temporary) / 'preserving-recovery'
    root.mkdir()
    peer = dns = process = None
    report = {}
    state = root / 'dns.json'
    control = root / 'command'

    def publish(address):
        staging = state.with_suffix('.tmp')
        staging.write_text(json.dumps({'address': address}))
        staging.replace(state)

    def signal_driver(action):
        staging = control.with_suffix('.tmp')
        staging.write_text(action)
        staging.replace(control)

    def ns(*args, **kwargs):
        return command('ip', 'netns', 'exec', namespace, *args, **kwargs)

    def status():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(5)
            channel.connect('/var/run/amneziavpn/daemon.socket')
            channel.sendall(b'{"type":"status"}\n')
            raw = bytearray()
            while b'\n' not in raw:
                data = channel.recv(65536)
                if not data:
                    raise EOFError('service IPC closed')
                raw.extend(data)
            return json.loads(raw.split(b'\n')[0])

    def peer_stats():
        result = ns('python3', '-c',
                    'import urllib.request;print(urllib.request.urlopen("http://127.0.0.1:18080/stats",timeout=5).read().decode())',
                    stdout=subprocess.PIPE, text=True)
        return json.loads(result.stdout)

    try:
        command(qt_probe, 'off')
        command('ip', 'netns', 'add', namespace)
        command('ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', namespace)
        command('ip', 'addr', 'add', '10.204.0.1/30', 'dev', host_if)
        command('ip', 'link', 'set', host_if, 'up')
        ns('ip', 'link', 'set', 'lo', 'up')
        ns('ip', 'link', 'set', 'eth0', 'up')
        ns('ip', 'addr', 'add', '10.204.0.2/30', 'dev', 'eth0')
        ns('ip', 'route', 'add', 'default', 'via', '10.204.0.1')
        for address in ('1.1.1.1', '8.8.8.8', '192.0.2.10', '192.0.2.20'):
            ns('ip', 'addr', 'add', address + '/32', 'dev', 'eth0')
            command('ip', 'route', 'add', address + '/32', 'via', '10.204.0.2', 'dev', host_if)
        for transport in ('awg', 'wireguard'):
            fixture = root / (transport + '.json')
            peer = subprocess.Popen(['ip', 'netns', 'exec', namespace, str(peer_binary), '--transport', transport,
                                     '--shared-ip', '192.0.2.10', '--bind-ip', '127.0.0.1', '--persistent', '--bulk',
                                     '--config', str(fixture)], stdout=subprocess.PIPE, text=True)
            assert select.select([peer.stdout], [], [], 15)[0] and peer.stdout.readline().startswith('READY')
            profile = json.loads(fixture.read_text())
            data = profile[transport + '_config_data']
            port = data['port']
            data['hostName'] = 'endpoint.test'
            profile['sing_box_routing'] = {'version': 1, 'default': 'vpn', 'rules': []}
            profile_file = root / ('profile-' + transport + '.json')
            profile_file.write_text(json.dumps(profile))
            original = profile_file.read_bytes()
            publish('192.0.2.10')
            dns = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable,
                                    str(Path(__file__).with_name('endpoint_migration_acceptance.py')),
                                    '--node', str(state), str(fixture), str(port)])
            time.sleep(.2)
            for strict in (False, True):
                publish('192.0.2.10')
                command(qt_probe, 'on' if strict else 'off')
                control.unlink(missing_ok=True)
                events = []
                errors = []
                stop_io = threading.Event()
                counters = {'echo': 0, 'bulk': 0}
                sockets = []
                process = subprocess.Popen([str(driver), str(profile_file), str(control)],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                current = process

                def read_events():
                    for line in current.stdout:
                        row = json.loads(line)
                        events.append(row)
                        if row.get('event') == 'failed':
                            errors.append('production protocol failed: ' + json.dumps(row))

                reader = threading.Thread(target=read_events, daemon=True)
                reader.start()

                def wait_for(predicate, reason, timeout=70):
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        assert not errors, errors
                        if predicate():
                            return
                        assert process.poll() is None, 'production protocol exited'
                        time.sleep(.05)
                    raise AssertionError(reason)

                threads = []
                try:
                    wait_for(lambda: any(row.get('event') == 'status' and row.get('preserved') for row in events),
                             'runtime ownership was not confirmed', 25)
                    initial = status()
                    assert initial.get('preserves_connections') and initial.get('runtime_alive')
                    runtime, pid = initial['runtime_id'], initial['runtime_pid']
                    capture = socket.if_nametoindex('amnrouting0')
                    fake = resolve('vpn.test')
                    before = peer_stats()
                    echo = socket.create_connection((fake, 18081), timeout=10)
                    sockets.append(echo)
                    assert receive(echo, 4) == b'VPN\n'
                    bulk = socket.create_connection((fake, 18444), timeout=10)
                    sockets.append(bulk)
                    bulk.sendall(struct.pack('!I', 64 << 20))
                    assert receive(bulk, 4) == b'VPN\n'
                    for connection in sockets:
                        connection.settimeout(60)

                    def echo_loop():
                        try:
                            while not stop_io.is_set():
                                payload = struct.pack('!Q', counters['echo'])
                                echo.sendall(payload)
                                assert receive(echo, len(payload)) == payload
                                counters['echo'] += 1
                                stop_io.wait(.1)
                        except (OSError, EOFError, AssertionError) as error:
                            if not stop_io.is_set():
                                errors.append(type(error).__name__ + ': original echo failed')

                    def bulk_loop():
                        try:
                            while not stop_io.is_set():
                                payload = receive(bulk, 4096)
                                assert payload == b'Z' * len(payload)
                                counters['bulk'] += len(payload)
                                stop_io.wait(.05)
                        except (OSError, EOFError, AssertionError) as error:
                            if not stop_io.is_set():
                                errors.append(type(error).__name__ + ': original bulk failed')

                    for work in (echo_loop, bulk_loop):
                        thread = threading.Thread(target=work, daemon=True)
                        thread.start()
                        threads.append(thread)
                    wait_for(lambda: counters['echo'] >= 3 and counters['bulk'] >= 12288, 'streams never started')
                    binding_event = len(events)
                    baseline = dict(counters)
                    signal_driver('network')
                    wait_for(lambda: not control.exists(), 'network signal was not consumed', 5)
                    signal_driver('drop_ipc')
                    wait_for(lambda: any(row.get('event') == 'ipc_dropped' for row in events), 'IPC loss was not exercised', 5)
                    wait_for(lambda: counters['echo'] >= baseline['echo'] + 5, 'IPC repair interrupted echo', 10)
                    assert status()['runtime_id'] == runtime
                    publish('192.0.2.20')
                    baseline = dict(counters)

                    def migrated():
                        current = status()
                        assert current['runtime_id'] == runtime and current['runtime_pid'] == pid
                        assert socket.if_nametoindex('amnrouting0') == capture
                        return (current.get('underlay_recovery', {}).get('endpoint_changes', 0) >= 1 and
                                counters['echo'] >= baseline['echo'] + 3 and counters['bulk'] >= baseline['bulk'] + 12288)

                    wait_for(migrated, 'domain migration did not preserve the original streams')
                    assert not [row for row in events[binding_event:] if row.get('event') == 'state' and row['state'] != 4], events
                    assert resolve('vpn.test') == fake, 'FakeIP identity changed during recovery'
                    after = peer_stats()
                    assert after['vpn_tcp'] == before['vpn_tcp'] + 1, 'a replacement echo connection concealed the interruption'
                    assert after['bulk_tcp'] == before['bulk_tcp'] + 1, 'a replacement bulk connection concealed the interruption'
                    assert profile_file.read_bytes() == original, 'saved endpoint/keys were rewritten'
                    observations = state.with_suffix('.queries.jsonl')
                    names = [json.loads(line) for line in observations.read_text().splitlines()]
                    assert names and set(names) == {'endpoint.test'}, 'application DNS escaped through endpoint bootstrap'

                    signal_driver('stop')
                    process.wait(timeout=15)
                    assert process.returncode == 0, 'explicit stop did not finish with service acknowledgement'
                    assert not status().get('runtime_alive'), 'explicit stop left a live runtime'
                    report[transport + ('-strict' if strict else '-open')] = {
                        'same_runtime_pid_tun': 'PASS', 'same_echo_bulk_sockets': 'PASS', 'signal_burst_and_ipc_loss': 'PASS',
                        'native_domain_rotation': 'PASS', 'fakeip_and_saved_profile': 'PASS', 'explicit_stop': 'PASS'}
                finally:
                    stop_io.set()
                    for connection in sockets:
                        try:
                            connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        connection.close()
                    for thread in threads:
                        thread.join(timeout=5)
                    if process is not None and process.poll() is None:
                        signal_driver('stop')
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                    process = None
                    reader.join(timeout=5)
            dns.terminate()
            dns.wait(timeout=5)
            dns = None
            peer.terminate()
            peer.wait(timeout=10)
            peer = None
        return report
    finally:
        command(qt_probe, 'off')
        for child in (process, dns, peer):
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        subprocess.run(['ip', 'link', 'del', host_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        subprocess.run(['ip', 'netns', 'del', namespace], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
