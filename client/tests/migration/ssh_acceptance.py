#!/usr/bin/env python3
"""Run in a disposable root container with sshd; all identities are synthetic."""
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import tempfile
import time


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with scripts/local-tests/migration-ssh.sh")
    subprocess.run(["useradd", "-m", "-s", "/bin/sh", "-p", "x", "migration-test"], check=True)
    uid = pwd.getpwnam("migration-test").pw_uid
    with tempfile.TemporaryDirectory(prefix="amnezia-ssh-fixture-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        for name in ("host", "client"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        (root / "authorized_keys").write_bytes((root / "client.pub").read_bytes())
        (root / "authorized_keys").chmod(0o644)
        remote = root / "remote"
        remote.mkdir(mode=0o700)
        os.chown(remote, uid, uid)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        config = root / "sshd_config"
        config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {root / 'host'}\nPidFile {root / 'pid'}\nAuthorizedKeysFile {root / 'authorized_keys'}\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nAllowUsers migration-test\nSubsystem sftp internal-sftp\nLogLevel DEBUG3\n")
        Path("/run/sshd").mkdir(exist_ok=True)
        log = root / "sshd.log"
        daemon = subprocess.Popen(["/usr/sbin/sshd", "-D", "-f", str(config), "-E", str(log)])
        try:
            for _ in range(100):
                if daemon.poll() is not None:
                    raise AssertionError("SSH fixture stopped")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            result = subprocess.run(["/tmp/migration-tests/migration_ssh_harness", "127.0.0.1", str(port), "migration-test", str(root / "client"), str(remote)], capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(f"SSH transport harness failed: {result.returncode}; {result.stderr[-1000:]}")
            report = json.loads(result.stdout)
            assert all(report.values())
            assert (remote / "snapshot.bin").stat().st_mode & 0o777 == 0o600
            assert not (remote / "must-not-exist").exists(), "canceled command was sent to the server"
            events = log.read_text()
            # Discovery and rejected fingerprint connections never authenticate.
            assert events.count("Accepted publickey for migration-test") == 1
            assert "method password" not in events
            print("PASS: unauthenticated discovery, pinned host key before auth, exit status, exclusive SFTP, private permissions and SHA256")
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)


if __name__ == "__main__":
    main()
