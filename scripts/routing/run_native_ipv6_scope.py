#!/usr/bin/env python3
"""Native IPv6 source/scoped-route probe, not a production OpenVPN acceptance.

Two independent origins share a synthetic address behind two owned TUNs. The
sender is the OS TCP stack. Never run on the user's desktop: Darwin requires an
explicitly enabled hosted runner; Linux requires an empty network namespace.
No default route, resolver, firewall setting or existing interface is changed.
"""
import argparse
from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import socket
import subprocess
import time


def command(*args):
    output = subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10)
    if args[0] == '/sbin/route':
        print(json.dumps({'route_command': list(args), 'output': output}), flush=True)
    return output


def reply(peer):
    assert select.select([peer.stdout], [], [], 10)[0], 'peer response timed out'
    line = peer.stdout.readline()
    assert line, 'peer exited before response'
    return json.loads(line)


def stop_peer(peer):
    if peer.poll() is None:
        try:
            peer.stdin.write('stop\n')
            peer.stdin.flush()
        except BrokenPipeError:
            pass  # wait() below still reports a failed peer.
    try:
        assert peer.wait(timeout=5) == 0, 'peer failed'
    except subprocess.TimeoutExpired:
        peer.kill()
        peer.wait(timeout=5)
        raise
    finally:
        peer.stdin.close()
        peer.stdout.close()


def echo(conn, expected, message):
    conn.sendall(message.encode() + b'\n')
    data = b''
    while not data.endswith(b'\n'):
        chunk = conn.recv(4096)
        assert chunk, 'original TCP closed'
        data += chunk
    assert data == f'{expected}:{message}\n'.encode(), (data, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    system = platform.system()
    assert os.geteuid() == 0, 'requires privileges only inside the owned lab'
    if system == 'Darwin':
        assert os.environ.get('AMNEZIA_NATIVE_IPV6_LAB') == 'owned-runner'
        assert os.environ.get('GITHUB_ACTIONS') == 'true'
    elif system == 'Linux':
        assert os.environ.get('AMNEZIA_NATIVE_IPV6_LAB') == 'isolated-container'
        assert {r['ifname'] for r in json.loads(command('ip', '-j', 'link'))} == {'lo'}
        command('ip', 'link', 'set', 'lo', 'up')
    else:
        raise AssertionError('supports Darwin/Linux only')
    # Random ULA /48 avoids colliding with a runner's existing test fixtures.
    prefix = 'fd' + secrets.token_hex(5)
    prefix = ':'.join(prefix[i:i+4] for i in range(0, 12, 4))
    remote = str(ipaddress.IPv6Address(prefix + '::1'))
    sources = {tag: str(ipaddress.IPv6Address(prefix + suffix)) for tag, suffix in (('A', '::a'), ('B', '::b'))}
    if system == 'Darwin':
        original = subprocess.run(['/sbin/route', '-n', 'get', '-inet6', remote], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        for line in original.stdout.splitlines():
            if line.strip().startswith('destination:'):
                assert line.split(':', 1)[1].strip() != remote, 'destination already has a host route'
    peers, devices = {}, {}
    with ExitStack() as cleanup:
        for index, tag in enumerate(('A', 'B')):
            peer = subprocess.Popen([str(args.peer.resolve()), '--address', remote, '--tag', tag],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            cleanup.callback(stop_peer, peer)
            ready = reply(peer)
            name = ready['device']
            assert ready == {'ready': True, 'device': name, 'address': remote, 'tag': tag}
            assert re.fullmatch(r'utun\d+' if system == 'Darwin' else r'amnv6\d+', name)
            peers[tag], devices[tag] = peer, name
            if system == 'Darwin':
                command('/sbin/ifconfig', name, 'inet6', sources[tag], 'prefixlen', '128', 'alias')
                command('/sbin/ifconfig', name, 'up')
                deadline = time.monotonic() + 5
                while 'tentative' in command('/sbin/ifconfig', name):
                    assert time.monotonic() < deadline, 'owned IPv6 DAD did not finish'
                    time.sleep(.05)
                command('/sbin/route', '-n', 'add', '-inet6', '-host', remote, '-ifscope', name, '-interface', name)
                cleanup.callback(command, '/sbin/route', '-n', 'delete', '-inet6', '-host', remote, '-ifscope', name)
            else:
                command('ip', 'link', 'set', name, 'up')
                command('ip', '-6', 'addr', 'add', sources[tag] + '/128', 'dev', name, 'nodad')
                table = str(60000 + index)
                command('ip', '-6', 'route', 'add', remote + '/128', 'dev', name, 'table', table)
                cleanup.callback(command, 'ip', '-6', 'route', 'del', remote + '/128', 'dev', name, 'table', table)
                command('ip', '-6', 'rule', 'add', 'priority', str(32000 + index), 'from', sources[tag] + '/128', 'lookup', table)
                cleanup.callback(command, 'ip', '-6', 'rule', 'del', 'priority', str(32000 + index), 'from', sources[tag] + '/128', 'lookup', table)

        route_history = []

        def record_routes(stage):
            if system != 'Darwin':
                return
            table = command('/usr/sbin/netstat', '-rn', '-f', 'inet6')
            rows = [line for line in table.splitlines() if remote in line or prefix in line]
            entry = {'stage': stage, 'owned_destination_routes': rows}
            route_history.append(entry)
            print(json.dumps(entry), flush=True)

        def route(tag, initial=False):
            if system == 'Darwin':
                record_routes('before-' + tag)
                # XNU RTM_CHANGE uses rt_lookup(), which can select a scoped
                # row even for a scope-less request. RTM_DELETE uses the exact
                # radix key, so replace only the owned unscoped row and leave
                # both source-path pins intact.
                if not initial:
                    command('/sbin/route', '-n', 'delete', '-inet6', '-host', remote)
                command('/sbin/route', '-n', 'add', '-inet6', '-host', remote, '-interface', devices[tag])
                record_routes('after-' + tag)
                if initial:
                    cleanup.callback(command, '/sbin/route', '-n', 'delete', '-inet6', '-host', remote)
            else:
                command('ip', '-6', 'route', 'add' if initial else 'replace', remote + '/128', 'dev', devices[tag], 'src', sources[tag])
                if initial:
                    cleanup.callback(command, 'ip', '-6', 'route', 'del', remote + '/128')

        def connect(tag):
            conn = socket.create_connection((remote, 18443), timeout=3)
            cleanup.callback(conn.close)
            assert conn.getsockname()[0] == sources[tag], ('wrong native source', conn.getsockname(), tag)
            echo(conn, tag, 'new-' + tag)
            return conn

        def udp(tag):
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as conn:
                conn.settimeout(3)
                conn.sendto(b'new-udp', (remote, 18443))
                assert conn.recv(4096) == (tag + ':new-udp').encode()

        route('A', initial=True)
        old_a = connect('A')
        udp('A')
        route('B')
        old_b = connect('B')
        udp('B')
        try:
            echo(old_a, 'A', 'original-after-A-to-B')
        except Exception as error:
            # Preserve native evidence before ExitStack removes the owned
            # routes/TUNs. A timeout remains failed acceptance, not a retry.
            diagnostics = {}
            if system == 'Darwin':
                probes = {
                    'destination': ['/sbin/route', '-n', 'get', '-inet6', remote],
                    **{f'scope_{tag}': ['/sbin/route', '-n', 'get', '-inet6',
                                       remote, '-ifscope', device]
                       for tag, device in devices.items()},
                    **{f'interface_{tag}': ['/sbin/ifconfig', device]
                       for tag, device in devices.items()},
                }
                for label, argv in probes.items():
                    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, timeout=10)
                    diagnostics[label] = {'exit_code': result.returncode, 'output': result.stdout}
            for tag, peer in peers.items():
                peer.stdin.write('stats\n')
                peer.stdin.flush()
                diagnostics['peer_' + tag] = reply(peer)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({
                'os': system, 'status': 'FAIL', 'stage': 'original-after-A-to-B',
                'error': repr(error), 'remote': remote, 'sources': sources,
                'original_source': old_a.getsockname()[0],
                'route_history': route_history,
                'diagnostics': diagnostics,
            }, indent=2) + '\n')
            raise
        route('A')
        new_a = connect('A')
        udp('A')
        echo(old_a, 'A', 'original-after-B-to-A')
        echo(old_b, 'B', 'original-after-B-to-A')
        echo(new_a, 'A', 'new-after-B-to-A')
        accepted = {}
        for tag, peer in peers.items():
            peer.stdin.write('stats\n')
            peer.stdin.flush()
            accepted[tag] = reply(peer)['accepted_tcp']
        assert accepted == {'A': 2, 'B': 1}, ('old TCP silently reconnected', accepted)
    for name in devices.values():
        try:
            socket.if_nametoindex(name)
        except OSError:
            pass
        else:
            raise AssertionError('owned TUN remains after closing peer: ' + name)
    report = {'os': system, 'status': 'PASS', 'native_sender_tcp': True,
              'source_scoped_paths': 'PASS', 'original_tcp_both_directions': 'PASS',
              'new_tcp_udp_paths': 'PASS', 'accepted_tcp': accepted, 'owned_tuns_removed': True,
              'not_proven': ['production OpenVPN integration', 'physical network handover']}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
