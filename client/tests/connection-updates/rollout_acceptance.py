#!/usr/bin/env python3
"""Real AWG 2-wire-format -> protected AWG 3 with signed delivery and rollback."""
import base64
import importlib.util
import json
import hmac
import hashlib
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import urllib.request

SOURCE = Path(__file__).resolve().parents[2] / "server_scripts"
SPEC = importlib.util.spec_from_file_location("vpn_acceptance", Path(__file__).parent.parent / "protocol-update/acceptance.py")
vpn = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vpn)
run = vpn.run
SERVER = "amnezia-awg2"
CLIENT = "amnezia-protection-test-client"
TOOL_IMAGE = "amnezia-awg2:protection-fixture"
VOLUME = "amnezia-connection-updates-state"


def feed_command(action, request):
    return json.loads(run("docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--mount", f"type=volume,source={VOLUME},target=/data", "amnezia-connection-updates:1", action,
                          input=json.dumps(request)))


def main():
    labels = json.loads(run("docker", "info", "--format", "{{json .Labels}}"))
    assert "amnezia.test-environment=disposable" in labels, "requires an isolated test daemon"
    assert not run("docker", "ps", "-aq", "--filter", f"name=^/{SERVER}$").strip()
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        delivery = root / "delivery"
        shutil.copytree(SOURCE / "connection_updates", delivery)
        info = json.loads(run("sh", str(delivery / "install.sh"), str(delivery), "127.0.0.1"))
        host_binary = root / "updates"
        run("docker", "cp", "amnezia-connection-updates:/updates", str(host_binary))
        host_binary.chmod(0o700)
        build = root / "awg"
        build.mkdir()
        dockerfile = (SOURCE / "awg/Dockerfile").read_text()
        dockerfile += '\nRUN sed -i \'/^add_if() {$/,/^}$/c\\add_if() {\\n\\tcmd amneziawg-go "$INTERFACE"\\n}\' /usr/bin/awg-quick\n'
        (build / "Dockerfile").write_text(dockerfile)
        run("docker", "build", "--network", "host", "-t", TOOL_IMAGE, str(build))

        def key(command, value=None):
            return run("docker", "run", "--rm", "-i", "--entrypoint", "awg", TOOL_IMAGE, command, input=value).strip()

        server_key, client_key, psk = key("genkey"), key("genkey"), key("genpsk")
        server_public, client_public = key("pubkey", server_key + "\n"), key("pubkey", client_key + "\n")
        awg = "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 0\nS4 = 0\nH1 = 1001-1010\nH2 = 2001-2010\nH3 = 3001-3010\nH4 = 4001-4010\n"
        state = root / "state"
        folder = state / "awg"
        folder.mkdir(parents=True)
        config = f"[Interface]\nPrivateKey = {server_key}\nAddress = 10.87.0.1/24\nListenPort = 51820\n{awg}\n[Peer]\nPublicKey = {client_public}\nPresharedKey = {psk}\nAllowedIPs = 10.87.0.2/32\n"
        (folder / "awg0.conf").write_text(config)
        (folder / "awg0.conf").chmod(0o600)
        preserved = {"wireguard_server_private_key.key": server_key, "wireguard_server_public_key.key": server_public,
                     "wireguard_psk.key": psk, "clientsTable": '[{"clientId":"synthetic-existing-user"}]'}
        for name, value in preserved.items():
            (folder / name).write_text(value)
        assets, release = vpn.startup_assets("awg")
        for relative, data in assets.items():
            target = state / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data)
        (state / "mtu/current").symlink_to(release)
        startup = assets["start.sh"].replace("$AWG_SUBNET_IP", "10.87.0.1").replace("$WIREGUARD_SUBNET_CIDR", "24")
        (state / "start.sh").write_text(startup)
        (state / "start.sh").chmod(0o755)
        run("docker", "create", "--privileged", "--restart", "unless-stopped", "--log-driver", "none", "-p", "51820:51820/udp", "--name", SERVER, TOOL_IMAGE)
        run("docker", "cp", str(state) + "/.", SERVER + ":/opt/amnezia/")
        run("docker", "start", SERVER)
        vpn.ready(SERVER, "awg", "awg0")
        original_id = run("docker", "inspect", "-f", "{{.Id}}", SERVER).strip()
        run("docker", "run", "-d", "--privileged", "--network", "host", "--name", CLIENT, "--entrypoint", "sh", TOOL_IMAGE, "-c", "tail -f /dev/null")
        client_file = root / "rollclient.conf"

        def client_config(parameters):
            extensions = "".join(f"{k} = {v}\n" for k, v in parameters.items() if k not in ("hostName", "port", "server_pub_key"))
            return f"[Interface]\nPrivateKey = {client_key}\nAddress = 10.87.0.2/32\n{extensions}\n[Peer]\nPublicKey = {server_public}\nPresharedKey = {psk}\nAllowedIPs = 10.87.0.1/32\nEndpoint = 127.0.0.1:51820\nPersistentKeepalive = 1\n"

        old_parameters = dict(line.split(" = ", 1) for line in awg.strip().splitlines())
        client_file.write_text(client_config(old_parameters))
        client_file.chmod(0o600)
        run("docker", "cp", str(client_file), CLIENT + ":/tmp/rollclient.conf")
        run("docker", "exec", CLIENT, "awg-quick", "up", "/tmp/rollclient.conf")
        vpn.ping(CLIENT)
        request = {"host": "127.0.0.1", "expectedPublicKey": info["publicKey"], "expectedCertificate": info["certificate"]}

        def activate():
            return json.loads(run(str(host_binary), "activate-awg3", input=json.dumps(request)))

        assert activate()["result"] == "rejected", "unregistered static peer was not gated"
        vpn.ping(CLIENT)
        settings = {"hostName": "127.0.0.1", "port": 51820, "server_pub_key": server_public, **old_parameters}
        issued = feed_command("issue", {"container": SERVER, "clientPublicKey": client_public, "settings": settings})
        context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(base64.b64decode(info["certificate"])))
        pub_der = root / "signer.der"
        pub_der.write_bytes(bytes.fromhex("302a300506032b6570032100") + base64.b64decode(info["publicKey"]))

        private_der = root / "device.der"
        private_der.write_bytes(bytes.fromhex("302e020100300506032b656e04220420") + base64.b64decode(client_key))
        private_der.chmod(0o600)

        def fetch():
            url = "https://127.0.0.1:8443/v1/connections/" + issued["id"]
            http_request = urllib.request.Request(url, headers={"Authorization": "Bearer " + issued["token"]})
            with urllib.request.urlopen(http_request, context=context, timeout=5) as response:
                envelope = json.load(response)
            raw = base64.b64decode(envelope["payload"])
            payload_file, signature_file = root / "payload", root / "signature"
            payload_file.write_bytes(raw)
            signature_file.write_bytes(base64.b64decode(envelope["signature"]))
            run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub_der), "-keyform", "DER", "-rawin", "-in", str(payload_file), "-sigfile", str(signature_file))
            payload = json.loads(raw)
            assert payload["clientPublicKey"] == client_public
            challenge_der = root / "challenge.der"
            challenge_der.write_bytes(bytes.fromhex("302a300506032b656e032100") + base64.b64decode(payload["ackChallenge"]))
            shared = subprocess.run(["openssl", "pkeyutl", "-derive", "-inkey", str(private_der), "-keyform", "DER", "-peerkey", str(challenge_der), "-peerform", "DER"], capture_output=True, check=True).stdout
            proof = hmac.new(shared, b"amnezia-awg3-ready-v1\0" + raw, hashlib.sha256).digest()
            receipt = dict(envelope, features=["awg3-header-protection-v1"], proof=base64.b64encode(proof).decode())
            ack = urllib.request.Request(url + "/ack", data=json.dumps(receipt).encode(), headers={"Authorization": "Bearer " + issued["token"], "Content-Type": "application/json"})
            with urllib.request.urlopen(ack, context=context, timeout=5) as response:
                assert response.status == 204
            return payload

        assert activate()["reason"] == "clients_not_ready", "unconfirmed client was not gated"
        assert fetch()["revision"] == "1"

        # Simulate a command failure AFTER the actual atomic signed publication.
        wrappers = root / "wrappers"
        wrappers.mkdir()
        actual_docker = shutil.which("docker")
        wrapper = wrappers / "docker"
        wrapper.write_text("#!/usr/bin/env python3\nimport os,subprocess,sys\nreal=" + repr(actual_docker) + "\nargs=sys.argv[1:]\nif args and args[0]=='run' and args[-1] in ('publish-if','publish-if-live'):\n result=subprocess.run([real,*args],stdin=sys.stdin.buffer)\n sys.exit(42 if result.returncode==0 else result.returncode)\nos.execv(real,[real,*args])\n")
        wrapper.chmod(0o755)
        environment = dict(os.environ, PATH=str(wrappers) + os.pathsep + os.environ["PATH"])
        failed = subprocess.run([str(host_binary), "activate-awg3"], input=json.dumps(request), text=True, capture_output=True, env=environment, check=True)
        assert json.loads(failed.stdout)["result"] == "rolled_back", "post-publication error did not roll back"
        assert run("docker", "exec", SERVER, "cat", "/opt/amnezia/awg/awg0.conf") == config
        restored = fetch()
        assert restored["revision"] == "3" and "HeaderProtectionKey" not in restored["settings"]
        run("docker", "exec", CLIENT, "awg-quick", "down", "/tmp/rollclient.conf")
        run("docker", "exec", CLIENT, "awg-quick", "up", "/tmp/rollclient.conf")
        vpn.ping(CLIENT)
        result = activate()
        assert result["result"] == "applied", result.get("reason")
        published = fetch()
        assert published["revision"] == "4" and published["settings"]["HeaderProtectionKey"]
        # Apply only public protocol fields; the original device key/PSK remain.
        run("docker", "exec", CLIENT, "awg-quick", "down", "/tmp/rollclient.conf")
        client_file.write_text(client_config(published["settings"]))
        run("docker", "cp", str(client_file), CLIENT + ":/tmp/rollclient.conf")
        run("docker", "exec", CLIENT, "awg-quick", "up", "/tmp/rollclient.conf")
        vpn.ping(CLIENT)
        assert run("docker", "inspect", "-f", "{{.Id}}", SERVER).strip() == original_id
        for name, value in preserved.items():
            assert run("docker", "exec", SERVER, "cat", "/opt/amnezia/awg/" + name) == value
        assert run("docker", "exec", SERVER, "cat", "/opt/amnezia/start.sh") == startup
        assert run("docker", "exec", CLIENT, "awg", "show", "rollclient", "public-key").strip() == client_public
        print("PASS: real AWG activation, signed config delivery, unchanged peer identity, fresh protected traffic, post-publication rollback")


if __name__ == "__main__":
    main()
