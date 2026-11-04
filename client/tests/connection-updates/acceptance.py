#!/usr/bin/env python3
"""Run only in a disposable nested Docker daemon. No production VPN needed."""
import base64
import json
import pathlib
import subprocess
import urllib.request
import ssl
import time

ROOT = pathlib.Path(__file__).resolve().parents[2] / "server_scripts/connection_updates"

def run(*args, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout

def command(action, request):
    result = run("docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL",
                 "--mount", "type=volume,source=amnezia-connection-updates-state,target=/data",
                 "amnezia-connection-updates:1", action, data=json.dumps(request).encode())
    return json.loads(result)

def main():
    labels = json.loads(run("docker", "info", "--format", "{{json .Labels}}"))
    assert "amnezia.test-environment=disposable" in labels, "requires an isolated Docker daemon"
    info = json.loads(run("sh", str(ROOT / "install.sh"), str(ROOT), "127.0.0.1"))
    assert info["version"] == 1
    initial = info.copy()
    again = json.loads(run("sh", str(ROOT / "install.sh"), str(ROOT), "127.0.0.1"))
    assert initial == again, "idempotent install changed keys"
    settings = {"hostName": "vpn1.example.test", "port": 51820,
                "server_pub_key": base64.b64encode(b"P" * 32).decode()}
    request = {"clientPublicKey": base64.b64encode(b"C" * 32).decode(),
               "container": "amnezia-wireguard", "settings": settings}
    issued = command("issue", request)
    pem = ssl.DER_cert_to_PEM_cert(base64.b64decode(info["certificate"]))
    context = ssl.create_default_context(cadata=pem)
    url = "https://127.0.0.1:8443/v1/connections/" + issued["id"]
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + issued["token"]})
    def fetch():
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            assert response.headers["Cache-Control"] == "no-store"
            envelope = json.load(response)
            return json.loads(base64.b64decode(envelope["payload"]))
    for attempt in range(50):
        try:
            payload = fetch()
            break
        except urllib.error.URLError:
            if attempt == 49: raise
            time.sleep(0.1)
    assert payload["revision"] == "1"
    settings["hostName"] = "vpn2.example.test"
    command("publish", {"container": request["container"], "settings": settings})
    assert fetch()["revision"] == "2"
    run("docker", "restart", "amnezia-connection-updates")
    for attempt in range(50):
        try:
            payload = fetch()
            break
        except urllib.error.URLError:
            if attempt == 49: raise
            time.sleep(0.1)
    assert payload["revision"] == "2", "lost publication on restart"
    command("revoke", request)
    try:
        fetch()
    except urllib.error.HTTPError as error:
        assert error.code == 401
    else:
        raise AssertionError("revoked token accepted")
    print("PASS: install, pinned TLS, issue, publish, restart, revoke; existing identity preserved")

if __name__ == "__main__":
    main()
