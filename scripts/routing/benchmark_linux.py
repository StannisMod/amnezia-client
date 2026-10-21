#!/usr/bin/env python3
"""Controlled CI comparison of installed legacy AWG and current native capture.

This measures the Linux data path, not application UI or physical-device performance.
No profile, key, packet capture, or UAPI content is written to the report.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import select
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

from run_linux_acceptance import resolve


def transfer(address, size):
    expected = hashlib.sha256(b'Z' * size).hexdigest()
    began = time.monotonic()
    with socket.create_connection((address, 18444), timeout=120) as connection:
        connection.sendall(struct.pack('!I', size))
        with connection.makefile('rb') as stream:
            assert stream.readline(16) == b'VPN\n', 'bulk stream bypassed AWG observer'
            digest = hashlib.sha256()
            received = 0
            while received < size:
                chunk = stream.read(min(65536, size - received))
                assert chunk, 'truncated bulk stream'
                digest.update(chunk)
                received += len(chunk)
            assert digest.hexdigest() == expected, 'bulk payload digest differs'
    elapsed = time.monotonic() - began
    return {'bytes': size, 'seconds': elapsed, 'mbps': size * 8 / elapsed / 1e6,
            'payload_sha256': expected, 'observer': 'VPN'}


def resources(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    rss = next(int(line.split()[1]) for line in status if line.startswith('VmRSS:'))
    return {'cpu_seconds': ticks / os.sysconf('SC_CLK_TCK'), 'rss_kib': rss}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--legacy', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    ns, host = 'amnezia-routing-bench', 'amnrbench-host'
    interface = 'amnbench0'
    sock_path = Path('/var/run/amneziawg') / (interface + '.sock')
    assert not sock_path.exists(), 'benchmark UAPI name is occupied'
    process = peer = None
    namespace_owned = host_owned = False
    report = {'result': 'FAIL', 'scope': 'Linux CI data path; not UI, mobile or physical hardware',
              'source_sha': os.environ.get('GITHUB_SHA'), 'kernel': platform.release(),
              'cpu_count': os.cpu_count(), 'cpu_affinity': sorted(os.sched_getaffinity(0)),
              'legacy_version': '3.1.20260814', 'mtu': 1280,
              'binary_sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for name, path in [('legacy', args.legacy), ('routed', args.helper), ('peer', args.peer)]},
              'measurements': {}}
    def run(*parts, **options):
        return subprocess.run(list(map(str, parts)), check=True, **options)
    def ip(*parts):
        return run('ip', *parts, capture_output=True, text=True).stdout
    def ns_ip(*parts):
        return ip('-n', ns, *parts)
    def stop(routed):
        nonlocal process
        if process is None:
            return
        if process.poll() is None:
            if routed:
                process.stdin.write('stop\n'); process.stdin.flush()
            else:
                process.terminate()
        assert process.wait(timeout=15) == 0, 'benchmark backend did not close cleanly'
        process = None
    try:
        ip('netns', 'add', ns); namespace_owned = True
        ip('link', 'add', host, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', ns); host_owned = True
        ip('addr', 'add', '10.0.2.2/24', 'dev', host)
        ip('link', 'set', host, 'up')
        ns_ip('link', 'set', 'lo', 'up')
        ns_ip('addr', 'add', '10.0.2.15/24', 'dev', 'eth0')
        ns_ip('link', 'set', 'eth0', 'up')
        ns_ip('route', 'add', 'default', 'via', '10.0.2.2')
        with tempfile.TemporaryDirectory() as private:
            private = Path(private)
            fixture = private / 'fixture.json'
            peer = subprocess.Popen([str(args.peer.resolve()), '--bulk', '--config', str(fixture)], stdout=subprocess.PIPE, text=True)
            assert select.select([peer.stdout], [], [], 15)[0] and peer.stdout.readline().startswith('READY'), 'peer not ready'
            profile = json.loads(fixture.read_text())
            cfg = profile['awg_config_data']
            for label, routed in [('legacy_awg', False), ('routed_sing_box_awg', True)]:
                began = time.monotonic()
                if routed:
                    profile['sing_box_routing'] = {'version': 1, 'default': 'vpn', 'rules': []}
                    process = subprocess.Popen(['ip', 'netns', 'exec', ns, str(args.helper.resolve()), '--no-system-dns', '--cache-dir', str(private / 'cache')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
                    messages = queue.Queue()
                    def drain(stream):
                        for line in stream:
                            messages.put(json.loads(line))
                        messages.put({'type': 'eof'})
                    threading.Thread(target=drain, args=(process.stdout,), daemon=True).start()
                    process.stdin.write(json.dumps(profile) + '\n'); process.stdin.flush()
                    ready = connected = False
                    deadline = time.monotonic() + 30
                    while not (ready and connected):
                        row = messages.get(timeout=max(0.1, deadline - time.monotonic()))
                        assert row['type'] not in ('error', 'eof'), 'routed benchmark startup failed'
                        ready |= row['type'] == 'ready'; connected |= row['type'] == 'connected'
                else:
                    process = subprocess.Popen(['ip', 'netns', 'exec', ns, str(args.legacy.resolve()), '-f', interface], env={**os.environ, 'LOG_LEVEL': 'silent'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    deadline = time.monotonic() + 15
                    while not sock_path.exists():
                        assert process.poll() is None and time.monotonic() < deadline, 'legacy UAPI not ready'
                        time.sleep(0.05)
                    lines = ['set=1', 'private_key=' + base64.b64decode(cfg['client_priv_key']).hex(), 'replace_peers=true']
                    for key in ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4'):
                        lines.append(key.lower() + '=' + str(cfg[key]))
                    lines += ['public_key=' + base64.b64decode(cfg['server_pub_key']).hex(),
                              f"endpoint={cfg['hostName']}:{cfg['port']}", 'persistent_keepalive_interval=1',
                              'replace_allowed_ips=true', 'allowed_ip=0.0.0.0/0']
                    with socket.socket(socket.AF_UNIX) as connection:
                        connection.settimeout(5); connection.connect(str(sock_path))
                        connection.sendall(('\n'.join(lines) + '\n\n').encode())
                        reply = b''
                        while b'\n\n' not in reply:
                            chunk = connection.recv(1024)
                            assert chunk, 'legacy UAPI closed before status'
                            reply += chunk
                        assert reply == b'errno=0\n\n', 'legacy UAPI rejected fixture'
                    ns_ip('addr', 'add', '10.77.0.1/32', 'dev', interface)
                    ns_ip('link', 'set', interface, 'mtu', '1280', 'up')
                    ns_ip('route', 'add', '10.77.0.2/32', 'dev', interface)
                initialized = time.monotonic() - began
                samples = []
                for index, size in enumerate([1 << 20] + [8 << 20] * 3):
                    before = resources(process.pid)
                    result = run('ip', 'netns', 'exec', ns, sys.executable, Path(__file__).resolve(), '--transfer', 'routed' if routed else 'legacy', str(size), capture_output=True, text=True, timeout=150)
                    sample = json.loads(result.stdout)
                    after = resources(process.pid)
                    sample.update(cpu_seconds=after['cpu_seconds'] - before['cpu_seconds'], rss_kib=after['rss_kib'])
                    sample['cpu_seconds_per_mib'] = sample['cpu_seconds'] / (size / (1 << 20))
                    if index:
                        samples.append(sample)
                report['measurements'][label] = {'backend_initialized_seconds': initialized, 'samples': samples,
                    'median_mbps': statistics.median(s['mbps'] for s in samples),
                    'median_cpu_seconds_per_mib': statistics.median(s['cpu_seconds_per_mib'] for s in samples),
                    'max_observed_rss_kib': max(s['rss_kib'] for s in samples)}
                stop(routed)
            old = report['measurements']['legacy_awg']; new = report['measurements']['routed_sing_box_awg']
            report['ratios_routed_over_legacy'] = {'throughput': new['median_mbps'] / old['median_mbps'],
                'cpu_per_mib': new['median_cpu_seconds_per_mib'] / old['median_cpu_seconds_per_mib'] if old['median_cpu_seconds_per_mib'] else None,
                'observed_rss': new['max_observed_rss_kib'] / old['max_observed_rss_kib']}
            report['result'] = 'PASS'
    finally:
        if process is not None:
            process.kill(); process.wait(timeout=10)
        if namespace_owned:
            subprocess.run(['ip', 'netns', 'exec', ns, str(args.helper.resolve()), '--recover'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if peer is not None:
            peer.terminate(); peer.wait(timeout=10)
        if host_owned:
            subprocess.run(['ip', 'link', 'del', host], capture_output=True)
        if namespace_owned:
            subprocess.run(['ip', 'netns', 'del', ns], capture_output=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--transfer':
        address = resolve('vpn.test') if sys.argv[2] == 'routed' else '10.77.0.2'
        print(json.dumps(transfer(address, int(sys.argv[3]))))
    else:
        main()
