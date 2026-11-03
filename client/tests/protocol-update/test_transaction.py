#!/usr/bin/env python3
"""Execute the production shell with a fault-injecting Docker boundary.

No daemon/root required. Only absolute log/lock locations are relocated. Shell
traps, file snapshots, canonical comparisons and flock execute unmodified.
"""
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "server_scripts/update_wireguard.sh"
CONF = "[Interface]\nPrivateKey = server-private\nListenPort = 51820\nHeaderProtectionKey = protection\n\n[Peer]\nPublicKey = alice\nPresharedKey = alice-psk\nAllowedIPs = 10.8.0.2/32\n\n[Peer]\nPublicKey = bob\nPresharedKey = bob-psk\nAllowedIPs = 10.8.0.3/32\n"


def docker():
    path = Path(os.environ["FAKE_DOCKER_STATE"])
    s = json.loads(path.read_text())
    a = sys.argv[2:]
    s["calls"].append(a)
    name = s["name"]
    containers = s["containers"]
    def lookup(value):
        return next((n for n, c in containers.items() if n == value or c.get("id") == value), value)
    code = 0
    out = ""
    cmd = a[0]
    failure = s.get("fail")
    if failure == cmd and not s.get("injected"):
        s["injected"] = True
        code = 1
    elif cmd == "inspect":
        key = lookup(a[-1])
        c = containers.get(key)
        if not c:
            code = 1
        elif "-f" not in a:
            out = json.dumps(c)
        else:
            f = a[a.index("-f") + 1]
            if "State.Running" in f:
                out = str(c["running"]).lower()
            elif f == "{{.Id}}":
                out = c["id"]
            elif f == "{{.Name}}":
                out = "/" + key
            elif ".Config.Labels" in f:
                out = c.get("label", "")
            elif "NetworkMode" in f:
                out = s.get("network", "default")
            elif ".Mounts" in f:
                out = s.get("mounts", "/lib/modules\n")
            elif "RestartPolicy" in f:
                out = c["restart"]
            elif "NetworkSettings" in f:
                out = "bridge\namnezia-dns-net\n"
            elif "HostPort" in f:
                out = "51820"
            elif "HostIp" in f:
                out = s.get("host_ip", "")
            elif "len" in f:
                out = "1"
            else:
                raise AssertionError(f)
    elif cmd == "exec":
        c = containers[lookup(a[1])]
        if a[2] == "cat":
            out = s.get("disk_conf", CONF)
        elif a[3] == "--version":
            out = "tools v1.0.test"
        elif a[3] == "show":
            code = 0 if c["running"] and c.get("healthy", True) else 1
        elif a[3] == "showconf":
            out = CONF
            if c["identity"] == "new" and failure == "peer-loss":
                out = out.replace("PresharedKey = alice-psk", "PresharedKey = WRONG")
            if c["identity"] == "new" and failure == "swap-peers":
                out = out.replace("alice-psk", "temp").replace("bob-psk", "alice-psk").replace("temp", "bob-psk")
            if c["identity"] == "new" and failure == "restart-loss" and s.get("restarted"):
                out = "[Interface]\nPrivateKey = different\n"
    elif cmd == "image":
        out = "sha256:candidate"
    elif cmd == "run":
        out = "tools v1.0.test"
    elif cmd == "build":
        assert containers[name]["running"], "old VPN must serve throughout build"
    elif cmd == "update":
        containers[lookup(a[-1])]["restart"] = a[1].split("=", 1)[1]
    elif cmd in ("stop", "start", "restart"):
        c = containers[lookup(a[1])]
        if failure == "rollback-failure" and cmd == "start":
            code = 1
        else:
            c["running"] = cmd != "stop"
        if cmd == "restart":
            s["restarted"] = True
        if cmd == "stop" and failure == "hup":
            path.write_text(json.dumps(s))
            os.kill(os.getppid(), signal.SIGHUP)
    elif cmd == "rename":
        containers[a[2]] = containers.pop(lookup(a[1]))
    elif cmd == "create":
        assert not any(c["running"] for c in containers.values())
        assert a[-1] == "sha256:candidate", "use the pinned image ID"
        containers[name] = {"identity": "new", "id": "new-id", "running": False, "restart": "no",
                            "label": a[a.index("--label") + 1].split("=", 1)[1]}
        out = "new-container-id"
    elif cmd == "cp":
        if ":" in a[1]:
            dest = Path(a[2])
            folder = dest / ("awg" if s["kind"] == "awg" else "wireguard")
            folder.mkdir(parents=True)
            (folder / ("awg0.conf" if s["kind"] == "awg" else "wg0.conf")).write_text(s.get("disk_conf", CONF))
            (folder / "clientsTable").write_text('[{"name":"Alice"},{"name":"Bob"}]')
            (folder / "wireguard_server_private_key.key").write_text("server-private")
            (dest / "start.sh").write_text("original-startup")
        else:
            src = Path(a[1])
            assert (src / "start.sh").read_text() == "original-startup"
            s["copied"] = sorted(str(p.relative_to(src)) for p in src.rglob("*") if p.is_file())
    elif cmd == "rm":
        containers.pop(lookup(a[-1]))
    elif cmd == "network":
        pass
    else:
        raise AssertionError(a)
    if failure == "hup-" + cmd and not s.get("injected"):
        s["injected"] = True
        path.write_text(json.dumps(s))
        os.kill(os.getppid(), signal.SIGHUP)
    path.write_text(json.dumps(s))
    if out:
        sys.stdout.write(out)
    sys.exit(code)


class TransactionTest(unittest.TestCase):
    def run_case(self, failure=None, kind="wireguard", **options):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            stage = root / "amnezia-update-aabb-0011"
            stage.mkdir()
            (stage / "Dockerfile").write_text("FROM test")
            script = SOURCE.read_text().replace("/var/lib/amnezia/updates", str(root / "updates")).replace(
                "/tmp/amnezia-update-", str(root / "amnezia-update-"))
            runner = root / "update.sh"
            runner.write_text(script)
            tools = root / "bin"
            tools.mkdir()
            (tools / "docker").write_text(f'#!/bin/sh\nexec "{sys.executable}" "{Path(__file__).resolve()}" --fake-docker "$@"\n')
            (tools / "sleep").write_text("#!/bin/sh\nexit 0\n")
            for p in tools.iterdir():
                p.chmod(0o755)
            name = "amnezia-awg2" if kind == "awg" else "amnezia-wireguard"
            state = root / "docker.json"
            state.write_text(json.dumps(dict(name=name, kind=kind, fail=failure, calls=[],
                containers={name: dict(identity="original", id="original-id", running=True, restart="unless-stopped")}, **options)))
            lock = None
            if failure == "busy":
                (root / "updates").mkdir()
                lock = (root / "updates" / f"{name}.lock").open("w")
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                r = subprocess.run(["sh", str(runner), kind, str(stage)], text=True,
                    capture_output=True, timeout=15, env=dict(os.environ,
                    PATH=f"{tools}:{os.environ['PATH']}", FAKE_DOCKER_STATE=str(state)))
            finally:
                if lock:
                    lock.close()
            s = json.loads(state.read_text())
            results = list((root / "updates").glob("*/result"))
            logs = "\n".join(p.read_text() for p in (root / "updates").glob("*/update.log"))
            self.assertEqual(r.stderr, "", logs)
            result = r.stdout.strip().removeprefix("amnezia_update=")
            self.assertIn(result, ("ok", "busy", "rejected", "rolled_back", "rollback_failed"), logs)
            if result == "ok":
                self.assertEqual(s["containers"][name]["identity"], "new", logs)
                self.assertEqual(s["containers"][name]["restart"], "unless-stopped")
                backups = [c for n, c in s["containers"].items() if n != name]
                self.assertEqual(len(backups), 1)
                self.assertFalse(backups[0]["running"])
                self.assertEqual(backups[0]["restart"], "no")
                self.assertTrue(any(p.endswith("clientsTable") for p in s["copied"]))
                for p in (root / "updates").rglob("server.conf"):
                    self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            elif result != "rollback_failed":
                self.assertEqual(s["containers"][name]["identity"], "original", logs)
                self.assertTrue(s["containers"][name]["running"], logs)
                self.assertEqual(s["containers"][name]["restart"], "unless-stopped", logs)
            if results:
                self.assertEqual(results[0].read_text().strip(), result)
            self.assertNotIn("server-private", r.stdout)
            s["log"] = logs
            return result, s

    def test_update_keeps_state_and_backup(self):
        for kind in ("wireguard", "awg"):
            with self.subTest(kind=kind):
                result, s = self.run_case(kind=kind)
                self.assertEqual(result, "ok", s["log"])

    def test_prepare_failures_never_stop_vpn(self):
        for failure in ("build", "run", "image"):
            with self.subTest(failure=failure):
                result, s = self.run_case(failure)
                self.assertEqual(result, "rejected")
                self.assertFalse(any(a[0] == "stop" for a in s["calls"]))

    def test_failures_restore_original(self):
        for failure in ("stop", "cp", "rename", "create", "start", "restart", "network", "peer-loss", "swap-peers", "restart-loss", "hup", "hup-rename", "hup-create", "hup-start"):
            with self.subTest(failure=failure):
                result, s = self.run_case(failure)
                self.assertEqual(result, "rolled_back", s["log"])

    def test_rollback_failure_is_reported(self):
        self.assertEqual(self.run_case("rollback-failure")[0], "rollback_failed")

    def test_legacy_awg_is_rejected_before_build(self):
        result, s = self.run_case(kind="awg", disk_conf=CONF.replace("HeaderProtectionKey = protection\n", ""))
        self.assertEqual(result, "rejected")
        self.assertFalse(any(a[0] in ("build", "stop") for a in s["calls"]))

    def test_custom_layout_is_rejected(self):
        for options in (dict(mounts="/lib/modules\n/opt/amnezia\n"), dict(network="host"), dict(host_ip="127.0.0.1")):
            with self.subTest(options=options):
                self.assertEqual(self.run_case(**options)[0], "rejected")

    def test_lock_prevents_concurrent_update(self):
        result, s = self.run_case("busy")
        self.assertEqual(result, "busy")
        self.assertEqual(s["calls"], [])


if __name__ == "__main__":
    if sys.argv[1:] and sys.argv[1] == "--fake-docker":
        docker()
    unittest.main()
