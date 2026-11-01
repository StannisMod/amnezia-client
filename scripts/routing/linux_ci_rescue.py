#!/usr/bin/env python3
"""Local, independently scheduled recovery for disposable installed-service CI.

Uses only the service's existing off/deactivate/stop and owned-helper recovery
operations. It never flushes host routes/firewalls or edits resolver files.
An activated rescue is failure evidence, never an acceptance PASS.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--confirm-disposable-runner', action='store_true', required=True)
    parser.add_argument('--qt-probe', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--deadline', type=int, default=420)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not 30 <= args.deadline <= 600:
        parser.error('requires root on a disposable Linux CI host and a bounded deadline')
    trigger = threading.Event()
    cancelled = threading.Event()
    signal.signal(signal.SIGUSR1, lambda *_: trigger.set())
    signal.signal(signal.SIGTERM, lambda *_: (cancelled.set(), trigger.set()))
    report = {'state': 'ARMED', 'deadline_seconds': args.deadline, 'operations': []}

    def save():
        temporary = args.report.with_suffix(args.report.suffix + '.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(args.report)

    def command(name, *argv, timeout=25):
        try:
            result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired):
            code = None
        report['operations'].append({'name': name, 'returncode': code})
        save()
        return code == 0

    save()
    deadline = time.monotonic() + args.deadline
    while not trigger.wait(min(60, max(0, deadline - time.monotonic()))):
        if time.monotonic() >= deadline:
            break
    if cancelled.is_set():
        report['state'] = 'CANCELLED_AFTER_ACCEPTANCE'
        save()
        return
    report['state'] = 'TRIGGERED'
    save()
    command('disable_strict_policy', args.qt_probe, 'off')
    try:
        with socket.socket(socket.AF_UNIX) as ipc:
            ipc.settimeout(5)
            ipc.connect('/var/run/amneziavpn/daemon.socket')
            ipc.sendall(b'{"type":"deactivate"}\n')
            ipc.recv(4096)  # discard contents; no profiles or raw events in report
        report['operations'].append({'name': 'deactivate', 'returncode': 0})
    except OSError:
        report['operations'].append({'name': 'deactivate', 'returncode': None})
    save()
    if not command('stop_service', 'systemctl', 'stop', 'AmneziaVPN'):
        command('terminate_owned_service_processes', 'systemctl', 'kill', '--kill-whom=all', '--signal=KILL', 'AmneziaVPN')
    helpers = list(Path('/opt/AmneziaVPN').rglob('amnezia-routing'))
    if len(helpers) == 1:
        command('recover_owned_native_state', helpers[0], '--recover')
    else:
        report['operations'].append({'name': 'recover_owned_native_state', 'returncode': None})
    command('start_service_for_policy_reset', 'systemctl', 'start', 'AmneziaVPN')
    command('reset_service_strict_policy', args.qt_probe, 'off')
    report['state'] = 'RECOVERY_ATTEMPTED'
    save()


if __name__ == '__main__':
    main()
