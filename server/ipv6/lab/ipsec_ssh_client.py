"""Invoke the real Qt updater through SSH inside the disposable daemon host."""
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import uuid


def update_with_qt(binary):
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0
    labels = json.loads(subprocess.check_output(
        ['docker', 'info', '--format', '{{json .Labels}}'], text=True))
    assert 'amnezia.test-environment=disposable' in labels
    binary = Path(binary).resolve(strict=True)
    user = 'ipsec-test-' + uuid.uuid4().hex[:8]
    sudoers = Path('/etc/sudoers.d') / user
    subprocess.run(['useradd', '-m', '-s', '/bin/sh', '-p', 'x', user], check=True)
    daemon = None
    try:
        sudoers.write_text(user + ' ALL=(root) NOPASSWD: ALL\n')
        sudoers.chmod(0o440)
        with tempfile.TemporaryDirectory(prefix='amnezia-ipsec-ssh-') as directory:
            root = Path(directory)
            # The fixture user must traverse to its authorized public key.
            root.chmod(0o755)
            for name in ('host', 'client'):
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                                '-f', str(root / name)], check=True)
            (root / 'authorized_keys').write_bytes((root / 'client.pub').read_bytes())
            (root / 'authorized_keys').chmod(0o644)
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            config = root / 'sshd_config'
            config.write_text(
                f'Port {port}\nListenAddress 127.0.0.1\nHostKey {root / "host"}\n'
                f'PidFile {root / "pid"}\nAuthorizedKeysFile {root / "authorized_keys"}\n'
                'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
                f'StrictModes no\nAllowUsers {user}\nSubsystem sftp internal-sftp\nLogLevel ERROR\n')
            Path('/run/sshd').mkdir(exist_ok=True)
            daemon = subprocess.Popen(['/usr/sbin/sshd', '-D', '-f', str(config),
                                       '-E', str(root / 'sshd.log')])
            for _ in range(100):
                if daemon.poll() is not None:
                    raise AssertionError('SSH fixture stopped')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise TimeoutError('SSH fixture did not listen')
            fixture = root / 'fixture.json'
            fixture.write_text(json.dumps({'host': '127.0.0.1', 'port': port,
                                           'user': user, 'keyFile': str(root / 'client')}))
            fixture.chmod(0o600)
            env = dict(os.environ, AMNEZIA_PROTOCOL_UPDATE_SSH_FIXTURE=str(fixture))
            stages_before = set(Path('/tmp').glob('amnezia-update-*'))
            result = subprocess.run([str(binary), 'testProtocolSoftwareUpdateOverSsh'],
                                    env=env, text=True, capture_output=True, timeout=360)
            if result.returncode:
                raise AssertionError('Qt SSH updater failed:\n' + result.stdout + result.stderr)
            assert '0 failed' in result.stdout and '0 skipped' in result.stdout, result.stdout
            stages = set(Path('/tmp').glob('amnezia-update-*')) - stages_before
            assert len(stages) == 1, 'Qt updater must create exactly one upload stage'
            stage = stages.pop()
            assert stat.S_IMODE(stage.stat().st_mode) == 0o700
            assets = {'update.sh', 'Dockerfile', 'start.sh', 'enable_ipv6.sh', 'network.sh'}
            assert {path.name for path in stage.iterdir()} == assets
            for asset in assets:
                assert stat.S_IMODE((stage / asset).stat().st_mode) == 0o600, asset
            print('PASS: production Qt updater uploads assets and completes the IPsec transaction over SSH', flush=True)
    finally:
        if daemon is not None:
            daemon.terminate()
            daemon.wait(timeout=10)
        sudoers.unlink(missing_ok=True)
        subprocess.run(['userdel', '-r', user], check=True, capture_output=True)
