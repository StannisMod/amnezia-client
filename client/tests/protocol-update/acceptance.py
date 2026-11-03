#!/usr/bin/env python3
"""Real unchanged-client traffic across update and rollback in a disposable environment.

Uses standard production Dockerfiles/startup and the production transaction.
Use a CI VM or the marked nested Docker daemon from scripts/local-tests/run.sh.
Never run against a user's main daemon: names match real Amnezia deployments.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def run(*args, input=None):
    r = subprocess.run(args, input=input, text=True, capture_output=True)
    if r.returncode:
        # Commands are safe to print; key material is carried via stdin/files.
        raise RuntimeError(f"{args}: {r.stderr[-2000:]}")
    return r.stdout


def ready(name, tool, interface):
    for _ in range(30):
        r = subprocess.run(["docker", "exec", name, tool, "show", interface], capture_output=True)
        if not r.returncode:
            return
        time.sleep(1)
    raise RuntimeError("VPN interface did not start")


def ping(client):
    for _ in range(15):
        r = subprocess.run(["docker", "exec", client, "ping", "-c", "1", "-W", "1", "10.87.0.1"], capture_output=True)
        if not r.returncode:
            return
        time.sleep(1)
    raise RuntimeError("Unchanged client failed to pass VPN traffic")


def main(kind):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        labels = json.loads(run("docker", "info", "--format", "{{json .Labels}}")) or []
        if "amnezia.test-environment=disposable" not in labels:
            raise SystemExit("Run on a disposable GitHub Actions VM or with scripts/local-tests/run.sh.")
    source = Path(__file__).resolve().parents[2] / "server_scripts"
    name = "amnezia-awg2" if kind == "awg" else "amnezia-wireguard"
    tool, iface = ("awg", "awg0") if kind == "awg" else ("wg", "wg0")
    state_dir = "awg" if kind == "awg" else "wireguard"
    client = "amnezia-update-test-client"
    original = name + ":acceptance-original"
    # Refuse to replace pre-existing resources, even on the test VM.
    assert not run("docker", "ps", "-aq", "--filter", f"name=^/{name}$").strip()
    run("docker", "network", "create", "amnezia-dns-net")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        build = root / "build"
        build.mkdir()
        dockerfile = (source / kind / "Dockerfile").read_text()
        (build / "Dockerfile").write_text(dockerfile)
        run("docker", "build", "-t", original, str(build))

        def key(command, value=None):
            return run("docker", "run", "--rm", "-i", "--entrypoint", tool, original, command, input=value).strip()

        server_key, client_key, psk = key("genkey"), key("genkey"), key("genpsk")
        server_public, client_public = key("pubkey", server_key + "\n"), key("pubkey", client_key + "\n")
        awg = ""
        if kind == "awg":
            awg = ("Jc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n"
                   "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = " + key("genkey") + "\n")
        state = root / "state"
        folder = state / state_dir
        folder.mkdir(parents=True)
        config = (f"[Interface]\nPrivateKey = {server_key}\nAddress = 10.87.0.1/24\nListenPort = 51820\n{awg}\n"
                  f"[Peer]\nPublicKey = {client_public}\nPresharedKey = {psk}\nAllowedIPs = 10.87.0.2/32\n")
        (folder / f"{iface}.conf").write_text(config)
        (folder / "wireguard_server_private_key.key").write_text(server_key)
        (folder / "wireguard_server_public_key.key").write_text(server_public)
        (folder / "wireguard_psk.key").write_text(psk)
        (folder / "clientsTable").write_text('[{"name":"Existing client","clientId":"retained"}]')
        startup = (source / kind / "start.sh").read_text()
        for var in ("AWG_SUBNET_IP", "WIREGUARD_SUBNET_IP"):
            startup = startup.replace("$" + var, "10.87.0.1")
        startup = startup.replace("$WIREGUARD_SUBNET_CIDR", "24")
        (state / "start.sh").write_text(startup)
        (state / "start.sh").chmod(0o755)
        run("docker", "create", "--privileged", "--restart", "unless-stopped", "--log-driver", "none",
            "-p", "51820:51820/udp", "-v", "/lib/modules:/lib/modules", "--name", name, original)
        run("docker", "cp", str(state) + "/.", name + ":/opt/amnezia/")
        run("docker", "network", "connect", "amnezia-dns-net", name)
        run("docker", "start", name)
        ready(name, tool, iface)
        run("docker", "run", "-d", "--privileged", "--network", "host", "--name", client,
            "--entrypoint", "sh", original, "-c", "tail -f /dev/null")
        client_config = root / "updateclient.conf"
        client_config.write_text(f"[Interface]\nPrivateKey = {client_key}\nAddress = 10.87.0.2/32\n{awg}\n"
                                f"[Peer]\nPublicKey = {server_public}\nPresharedKey = {psk}\n"
                                "AllowedIPs = 10.87.0.1/32\nEndpoint = 127.0.0.1:51820\nPersistentKeepalive = 1\n")
        run("docker", "cp", str(client_config), client + ":/tmp/updateclient.conf")
        run("docker", "exec", client, tool + "-quick", "up", "/tmp/updateclient.conf")
        ping(client)

        def update(file):
            stage = Path("/tmp/amnezia-update-" + str(uuid.uuid4()))
            stage.mkdir(mode=0o700)
            (stage / "Dockerfile").write_text(file)
            result = subprocess.run(["sudo", "sh", str(source / "update_wireguard.sh"), kind, str(stage)],
                                    text=True, capture_output=True)
            assert not result.stderr, result.stderr
            return result.stdout.strip()

        before_id = run("docker", "inspect", "-f", "{{.Id}}", name).strip()
        assert update(dockerfile) == "amnezia_update=ok"
        after_id = run("docker", "inspect", "-f", "{{.Id}}", name).strip()
        assert before_id != after_id
        ping(client)  # The client's keys, endpoint and config have not changed.
        copied = root / "after"
        run("docker", "cp", name + ":/opt/amnezia/.", str(copied))
        for path in state.rglob("*"):
            if path.is_file():
                assert path.read_bytes() == (copied / path.relative_to(state)).read_bytes(), path.name
        print(f"{kind}: replacement preserved files and existing-client traffic")

        # Tools exist and return a version, but the new entrypoint never starts
        # the VPN. The running tail must not be mistaken for a healthy protocol.
        broken = dockerfile + '\nENTRYPOINT ["sh", "-c", "tail -f /dev/null"]\n'
        assert update(broken) == "amnezia_update=rolled_back"
        assert run("docker", "inspect", "-f", "{{.Id}}", name).strip() == after_id
        assert run("docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", name).strip() == "unless-stopped"
        ping(client)
        print(f"{kind}: failed replacement restored original container and client traffic")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("wireguard", "awg"), required=True)
    main(parser.parse_args().kind)
