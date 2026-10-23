#!/usr/bin/env python3
"""Run the real installed service in a disposable systemd/network namespace.

The Docker bridge, private PID/cgroup namespaces and private system D-Bus keep
the runner's control connection outside the VPN. No host network, system D-Bus,
Docker socket or writable source directory is mounted in the container.
"""
import argparse
import os
from pathlib import Path
import subprocess
import time
import uuid


def run(*argv, **kwargs):
    kwargs.setdefault('check', True)
    return subprocess.run(list(map(str, argv)), timeout=kwargs.pop('timeout', 60), **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--qt-probe', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--diagnose-capture-mark', action='store_true')
    parser.add_argument('--helper', type=Path, help='diagnostic replacement; not installer acceptance')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    runtime = Path(os.environ['RUNNER_TEMP']).resolve()
    for path in (args.package, args.peer, args.qt_probe, args.helper):
        if path is not None:
            path.resolve(strict=True)
            if not (path.resolve().is_relative_to(repo) or path.resolve().is_relative_to(runtime)):
                parser.error('test inputs must be in the checkout or RUNNER_TEMP')
    report = args.report.resolve()
    name = 'routing-service-' + uuid.uuid4().hex[:12]
    image = name + ':test'
    run('docker', 'build', '--tag', image, repo / 'scripts/routing/linux-service-ci', timeout=600)
    try:
        run('docker', 'run', '--detach', '--name', name, '--privileged', '--cgroupns=private',
            '--tmpfs', '/run', '--tmpfs', '/run/lock', '--tmpfs', '/tmp',
            '--volume', f'{repo}:{repo}:ro', '--volume', f'{runtime}:{runtime}:ro',
            '--env', 'QT_QPA_PLATFORM=offscreen', image)

        def execute(*argv, **kwargs):
            return run('docker', 'exec', name, *argv, **kwargs)

        deadline = time.monotonic() + 60
        while True:
            running = run('docker', 'inspect', '--format', '{{.State.Running}}', name, stdout=subprocess.PIPE).stdout.strip()
            if running != b'true':
                raise RuntimeError('container init exited before systemd became ready; see boot log')
            state = execute('systemctl', 'is-system-running', stdout=subprocess.PIPE, check=False).stdout.strip()
            if state in (b'running', b'degraded'):
                break
            if time.monotonic() > deadline:
                raise RuntimeError('container systemd failed to boot')
            time.sleep(1)
        # Configure the base system resolver before the acceptance snapshot.
        # Once VPN testing starts, the real helper owns all resolver changes.
        execute('systemctl', 'start', 'dbus', 'systemd-resolved')
        execute('mount', '--bind', '/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf')
        execute('mkdir', '-p', '/artifacts')
        execute('env', 'QT_QPA_PLATFORM=offscreen', 'bash', str(repo / 'scripts/routing/install_service_in_container.sh'),
                str(args.package.resolve()), str(args.helper.resolve()) if args.helper else '', timeout=240)
        execute('python3', '-u', str(repo / 'scripts/routing/run_service_acceptance.py'),
                '--peer', str(args.peer.resolve()), '--qt-probe', str(args.qt_probe.resolve()),
                '--report', '/artifacts/' + report.name, '--resolver-cycles', '100', '--ci-rescue',
                *(['--diagnose-capture-mark'] if args.diagnose_capture_mark else []),
                *([] if args.helper else ['--require-notices']), timeout=720)
    finally:
        report.parent.mkdir(parents=True, exist_ok=True)
        # Preserve PID 1 output even if systemd never reached journald.
        with report.with_suffix('.boot.log').open('w') as log:
            subprocess.run(['docker', 'logs', name], stdout=log, stderr=subprocess.STDOUT, timeout=30, check=False)
        # Copy diagnostics even when acceptance, its watchdog or the container fails.
        subprocess.run(['docker', 'cp', name + ':/artifacts/.', str(report.parent)], timeout=30, check=False)
        with report.with_suffix('.journal.log').open('w') as log:
            subprocess.run(['docker', 'exec', name, 'journalctl', '--no-pager', '-u', 'AmneziaVPN', '-u', 'systemd-resolved'],
                           stdout=log, stderr=subprocess.STDOUT, timeout=30, check=False)
        subprocess.run(['docker', 'rm', '--force', name], timeout=30, check=False)
        subprocess.run(['docker', 'image', 'rm', image], timeout=30, check=False)


if __name__ == '__main__':
    main()
