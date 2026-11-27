#!/usr/bin/env python3
"""Offline certificate-authenticated Libreswan peer for the owned Windows VM.

Run only in its explicitly shared, otherwise loopback-only test namespace.
No client package, physical machine or hosted-platform result is synthesized.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if os.environ.get("AMNEZIA_IKEV2_DNS_NATIVE_TEST") != "isolated-fixture":
    raise RuntimeError("Requires an explicitly owned isolated fixture")
interfaces = json.loads(subprocess.check_output(["ip", "-j", "link"], text=True))
if {entry["ifname"] for entry in interfaces} != {"lo"}:
    raise RuntimeError("Refusing a namespace with non-fixture interfaces")
for kind in ("state", "policy"):
    if subprocess.check_output(["ip", "xfrm", kind], text=True).strip():
        raise RuntimeError("Refusing pre-existing XFRM ownership")
out = args.output
out.mkdir(parents=True, exist_ok=False)
os.chmod(out, 0o700)
(out / "fixture_server.source.py").write_bytes(Path(__file__).read_bytes())
log = (out / "setup.log").open("w")


def run(*command):
    subprocess.run(command, cwd=out, stdout=log, stderr=subprocess.STDOUT, check=True)


(out / "ca.ext").write_text(
    "basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
for kind, usage, subject in (
    ("server", "serverAuth", "10.0.2.2"),
    ("client", "clientAuth", "Amnezia IKEv2 native DNS fixture client"),
):
    (out / (kind + ".ext")).write_text(
        "basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage={usage},1.3.6.1.5.5.8.2.2\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        + ("subjectAltName=IP:10.0.2.2,DNS:10.0.2.2\n" if kind == "server" else ""))
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-subj", "/CN=" + subject, "-keyout", kind + ".key", "-out", kind + ".csr")
run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
    "-subj", "/CN=Amnezia IKEv2 native DNS fixture 20261125 CA", "-keyout", "ca.key", "-out", "ca.csr")
run("openssl", "x509", "-req", "-in", "ca.csr", "-signkey", "ca.key",
    "-days", "14", "-sha256", "-extfile", "ca.ext", "-out", "ca.pem")
for kind in ("server", "client"):
    run("openssl", "x509", "-req", "-in", kind + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-days", "14", "-sha256", "-extfile", kind + ".ext", "-out", kind + ".pem")
    run("openssl", "pkcs12", "-export", "-name", kind, "-inkey", kind + ".key",
        "-in", kind + ".pem", "-certfile", "ca.pem", "-passout", "pass:fixture-only", "-out", kind + ".p12")
run("openssl", "x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der")
run("openssl", "x509", "-in", "client.pem", "-outform", "DER", "-out", "client.der")
for key in out.glob("*.key"):
    os.chmod(key, 0o600)
nss = out / "nss"
nss.mkdir()
run("certutil", "-N", "-d", "sql:" + str(nss), "--empty-password")
run("pk12util", "-i", str(out / "server.p12"), "-d", "sql:" + str(nss), "-W", "fixture-only")
# Loopback commonly has disable_xfrm=1 and disable_policy=1 in containers.
# Use an owned dummy data link, without connecting this isolated namespace to
# any host/underlay network. The outer IKE/ESP transport remains loopback.
run("ip", "link", "add", "amnz-dns-peer", "type", "dummy")
run("ip", "link", "set", "amnz-dns-peer", "up")
run("ip", "addr", "add", "10.70.0.1/32", "dev", "amnz-dns-peer")
run("ip", "route", "add", "10.70.0.0/24", "dev", "amnz-dns-peer", "src", "10.70.0.1")
updown = out / "native-dns-updown.sh"
updown.write_text("""#!/bin/sh
set -eu
case "$PLUTO_VERB" in
    route-client|route-host)
        case "$PLUTO_PEER_CLIENT" in
            10.70.0.[2-9]/32|10.70.0.1[0-9]/32|10.70.0.20/32) ;;
            *) exit 1 ;;
        esac
        ip route replace "$PLUTO_PEER_CLIENT" dev amnz-dns-peer src 10.70.0.1
        ;;
esac
""")
updown.chmod(0o700)
config = out / "ipsec.conf"
config.write_text(f"""config setup
    protostack=netkey
    ikev1-policy=drop
    uniqueids=yes
    nhelpers=1
    dnssec-enable=no
    logfile={out}/pluto.log

conn native-ikev2-dns
    keyexchange=ikev2
    left=127.0.0.1
    leftid=@10.0.2.2
    leftcert=server
    leftsendcert=always
    leftupdown={updown}
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%fromcert
    rightca=%same
    rightaddresspool=10.70.0.2-10.70.0.20
    modecfgdns=10.70.0.1
    narrowing=yes
    ike=aes256-sha2_256;modp2048
    esp=aes_gcm128;modp2048
    pfs=yes
    dpddelay=10
    dpdtimeout=30
    dpdaction=clear
    auto=add
""")
run("ipsec", "addconn", "--config", str(config), "--checkconfig")

records = (out / "dns.jsonl").open("a", buffering=1)
record_lock = threading.Lock()


def answer(query, peer, transport):
    if len(query) < 12:
        return b""
    offset, labels = 12, []
    while offset < len(query) and query[offset]:
        length = query[offset]
        if length > 63 or offset + length + 1 >= len(query):
            return b""
        labels.append(query[offset + 1:offset + length + 1].decode("ascii", errors="replace"))
        offset += length + 1
    if offset + 5 > len(query):
        return b""
    end = offset + 5
    qtype, qclass = struct.unpack("!HH", query[offset + 1:end])
    with record_lock:
        records.write(json.dumps({"name": ".".join(labels), "type": qtype, "class": qclass,
                                  "peer": peer, "transport": transport}) + "\n")
    data = b""
    if qtype == 1:
        data = struct.pack("!HHHLH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton("192.0.2.123")
    elif qtype == 28:
        # A positive upstream witness distinguishes actual OFF suppression
        # from merely forwarding an upstream's own empty AAAA response.
        data = struct.pack("!HHHLH", 0xc00c, 28, 1, 5, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::123")
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(data), 0, 0) + query[12:end] + data


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        response = answer(query, self.client_address, "udp")
        if response:
            sock.sendto(response, self.client_address)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        def read(count):
            data = b""
            while len(data) < count:
                part = self.request.recv(count - len(data))
                if not part:
                    raise EOFError()
                data += part
            return data
        try:
            size, = struct.unpack("!H", read(2))
            response = answer(read(size), self.client_address, "tcp")
            self.request.sendall(struct.pack("!H", len(response)) + response)
        except (EOFError, OSError):
            pass


udp = socketserver.ThreadingUDPServer(("10.70.0.1", 53), UDP)
tcp = socketserver.ThreadingTCPServer(("10.70.0.1", 53), TCP)
for server in (udp, tcp):
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
pluto_log = (out / "pluto-console.log").open("w")
pluto = subprocess.Popen(["ipsec", "pluto", "--nssdir", str(nss), "--config", str(config),
                          "--nofork", "--stderrlog"], stdout=pluto_log, stderr=subprocess.STDOUT)
stop = threading.Event()
for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, lambda *_: stop.set())
try:
    deadline = time.monotonic() + 10
    while True:
        result = subprocess.run(["ipsec", "whack", "--status"], capture_output=True, text=True)
        if result.returncode == 0:
            break
        if pluto.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("Native pluto readiness failed; preserved console: " + pluto_log.name)
        time.sleep(.1)
    run("ipsec", "addconn", "--config", str(config), "--autoall")
    (out / "manifest.json").write_text(json.dumps({
        name: hashlib.sha256((out / name).read_bytes()).hexdigest()
        for name in ("fixture_server.source.py", "ca.der", "client.der", "client.p12")
    }, indent=2))
    (out / "ready.json").write_text(json.dumps({"native": "Libreswan", "dns": "10.70.0.1",
                                               "endpoint": "10.0.2.2", "fixture": str(out)}))
    print("READY: isolated certificate IKEv2 peer; native negotiation has not yet been accepted", flush=True)
    while not stop.wait(.2):
        if pluto.poll() is not None:
            raise RuntimeError("Native pluto exited")
finally:
    pluto.terminate()
    pluto.wait(timeout=10)
    for server in (udp, tcp):
        server.shutdown()
        server.server_close()
    records.close()
    log.close()
    pluto_log.close()
