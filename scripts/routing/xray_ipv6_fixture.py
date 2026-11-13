#!/usr/bin/env python3
"""Disposable Xray VLESS/TLS peer and real kernel IPv4/IPv6 TCP/UDP origins.

Only runs as root in Docker --network none. No host networking, external server,
system CA installation, or production credentials. Supply the pinned Xray CLI.
The Android acceptance runner consumes fixture.json and quic.der from --work.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
import uuid

TARGETS = ["198.51.100.2", "2001:db8:42::2", "fd42:4242::2", "64:ff9b::c000:201"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--debug", action="store_true", help="verbose logs for synthetic fixture traffic only")
    args = parser.parse_args()
    assert Path("/.dockerenv").exists() and os.geteuid() == 0, "only an owned rooted Docker fixture is supported"
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], text=True))
    assert {link["ifname"] for link in links} <= {"lo", "stability6"}, "use Docker --network none"
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o700)
    added, listeners = [], []
    peer = None
    peer_log = None
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())
    counters = {"tcp": {}, "udp": {}}
    lock = threading.Lock()
    def observe(kind, address):
        address = address.removeprefix("::ffff:")
        with lock:
            counters[kind][address] = counters[kind].get(address, 0) + 1
    def stream(connection):
        with connection:
            connection.settimeout(5)
            request = b""
            while len(request) < 128 and not request.endswith(b"\n"):
                part = connection.recv(128-len(request))
                if not part:
                    return
                request += part
            if request != b"route-proof\n":
                return
            observe("tcp", connection.getsockname()[0])
            connection.sendall(b"XRAY\n")
    def accept(server):
        while not done.is_set():
            try:
                connection, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=stream, args=(connection,), daemon=True).start()
    def packets(server):
        # One socket per origin preserves the actual IPv6 destination witness.
        while not done.is_set():
            try:
                data, remote = server.recvfrom(65535)
                observe("udp", server.getsockname()[0])
                server.sendto(b"XRAY:" + data, remote)
            except OSError:
                return
    class Control(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                data = json.dumps(counters).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(data)
        def do_POST(self):
            self.send_response(200); self.end_headers()
        def log_message(self, *_):
            pass
    try:
        for address in TARGETS:
            cidr = address + ("/128" if ":" in address else "/32")
            inventory = json.loads(subprocess.check_output(["ip", "-j", "addr", "show", "dev", "lo"], text=True))
            if any(item["local"] == address for link in inventory for item in link.get("addr_info", [])):
                continue  # Reuse a pre-existing fixture address; never delete it.
            subprocess.run(["ip", "addr", "add", cidr, "dev", "lo"], check=True)
            added.append(cidr)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=routing-xray.test", "-addext", "subjectAltName=DNS:routing-xray.test,IP:10.0.2.2",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(work/"server.key"),
                        "-out", str(work/"server.crt")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(work/"server.key", 0o600)
        subprocess.run(["openssl", "x509", "-in", str(work/"server.crt"), "-outform", "DER", "-out", str(work/"quic.der")], check=True)
        identity = str(uuid.uuid4())
        stream_options = {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [
            {"certificateFile": str(work/"server.crt"), "keyFile": str(work/"server.key")}]}}
        server_config = {"log": {"loglevel": "debug" if args.debug else "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": 38443,
            "protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": identity}]}, "streamSettings": stream_options}],
            # The pinned fork rejects private/documentation destinations by
            # default. Authorize only these owned origins and test ports.
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow",
                "ip": [ip + ("/128" if ":" in ip else "/32") for ip in TARGETS], "port": "18081-18082"}]}}]}
        (work/"server.json").write_text(json.dumps(server_config))
        client_config = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": 10808,
            "protocol": "socks", "settings": {"udp": True}}], "outbounds": [{"tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": "10.0.2.2", "port": 38443, "users": [{"id": identity, "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "routing-xray.test",
                "disableSystemRoot": True, "certificates": [{"usage": "verify", "certificate": (work/"server.crt").read_text().splitlines()}]}}}]}
        fixture = {"description": "Disposable Xray IPv6 fixture", "protocol": "xray", "hostName": "10.0.2.2", "dns1": "1.1.1.1",
            "xray_config_data": {"port": "38443", "config": json.dumps(client_config)}, "ipv6_test_destinations": TARGETS}
        for address in TARGETS:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            for kind, port, serve in ((socket.SOCK_STREAM, 18081, accept), (socket.SOCK_DGRAM, 18082, packets)):
                server = socket.socket(family, kind); listeners.append(server)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((address, port))
                if kind == socket.SOCK_STREAM:
                    server.listen()
                threading.Thread(target=serve, args=(server,), daemon=True).start()
        control = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Control)
        threading.Thread(target=control.serve_forever, daemon=True).start()
        peer_log = (work/"xray.log").open("w")
        peer = subprocess.Popen([str(args.xray.resolve()), "run", "-config", str(work/"server.json")], stdout=peer_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+10
        while True:
            assert peer.poll() is None, "Xray fixture failed; see xray.log"
            try:
                with socket.create_connection(("127.0.0.1", 38443), timeout=1):
                    break
            except OSError:
                assert time.monotonic() < deadline, "Xray listener timeout"
                time.sleep(.05)
        (work/"fixture.json").write_text(json.dumps(fixture))
        print("READY: VLESS/TLS and real kernel IPv4/GUA/ULA/NAT64 origins", flush=True)
        while not done.wait(.5):
            assert peer.poll() is None, "Xray fixture terminated"
    finally:
        done.set()
        if peer is not None and peer.poll() is None:
            peer.terminate(); peer.wait(timeout=10)
        if peer_log is not None:
            peer_log.close()
        for server in listeners:
            server.close()
        for cidr in reversed(added):
            subprocess.run(["ip", "addr", "del", cidr, "dev", "lo"], check=True)


if __name__ == "__main__":
    main()
