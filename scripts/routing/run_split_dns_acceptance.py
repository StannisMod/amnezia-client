#!/usr/bin/env python3
"""Split DNS and systemd-resolved proof inside a disposable, offline container.

Run only with --confirm-disposable-container. Two private network namespaces
hold the corporate DNS observer and encrypted peer; no real VPS is contacted.
"""
import argparse
import ipaddress
import json
import os
import pwd
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=20, **kwargs)


def dns_observer(log):
    """Independent synthetic corporate DNS and TCP observer."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("10.88.0.53", 53))
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("10.88.0.53", 18081))
    tcp.listen()

    def serve_client(client):
        with client:
            client.sendall(b"DIRECT\n")
            while True:
                payload = client.recv(4096)
                if not payload:
                    break
                client.sendall(payload)

    def serve_tcp():
        while True:
            client, _ = tcp.accept()
            threading.Thread(target=serve_client, args=(client,), daemon=True).start()

    threading.Thread(target=serve_tcp, daemon=True).start()
    print("READY", flush=True)
    while True:
        packet, source = udp.recvfrom(4096)
        udp.sendto(dns_response(packet, log), source)


def dns_response(packet, log):
    offset, labels = 12, []
    while packet[offset]:
        length = packet[offset]
        labels.append(packet[offset + 1:offset + 1 + length].decode("ascii"))
        offset += length + 1
    offset += 1
    kind, _ = struct.unpack_from("!HH", packet, offset)
    question = packet[12:offset + 4]
    with log.open("a") as output:
        output.write(".".join(labels).lower() + ".\n")
    answer = b""
    if kind == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("10.88.0.53")
    elif kind == 16:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 30, 7) + b"\x06DIRECT"
    response = struct.pack("!6H", struct.unpack_from("!H", packet)[0], 0x8180, 1, bool(answer), 0, 0) + question + answer
    return response


def tls_observer(log, cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.88.0.53", 8853))
    listener.listen()

    def read_exact(client, length):
        result = b""
        while len(result) < length:
            part = client.recv(length - len(result))
            if not part:
                raise EOFError()
            result += part
        return result

    def serve(client):
        try:
            with context.wrap_socket(client, server_side=True) as stream:
                stream.settimeout(10)
                while True:
                    length = struct.unpack("!H", read_exact(stream, 2))[0]
                    response = dns_response(read_exact(stream, length), log)
                    stream.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, EOFError):
            client.close()

    print("READY", flush=True)
    while True:
        client, _ = listener.accept()
        threading.Thread(target=serve, args=(client,), daemon=True).start()



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--dns-policy-fixture", type=Path, help="production Qt-generated site/DNS policies")
    parser.add_argument("--transport", choices=("awg", "wireguard"), default="awg")
    parser.add_argument("--confirm-disposable-container", action="store_true", required=True)
    args = parser.parse_args()
    if not Path("/.dockerenv").exists() or os.geteuid() != 0:
        parser.error("This test requires a disposable privileged Docker container.")
    temporary = Path("/tmp/split-dns-acceptance")
    temporary.mkdir(mode=0o700)
    processes, namespaces = [], []
    child = None
    report = {"split_dns": "FAIL", "transport": args.transport}
    automatic = json.loads(args.dns_policy_fixture.read_text()) if args.dns_policy_fixture else None
    script = Path(__file__).resolve()

    def network(name, iface, client, server):
        run("ip", "netns", "add", name)
        namespaces.append(name)
        run("ip", "link", "add", iface, "type", "veth", "peer", "name", "eth0", "netns", name)
        run("ip", "addr", "add", client + "/24", "dev", iface)
        run("ip", "link", "set", iface, "up")
        run("ip", "-n", name, "addr", "add", server + "/24", "dev", "eth0")
        run("ip", "-n", name, "link", "set", "eth0", "up")
        run("ip", "-n", name, "link", "set", "lo", "up")

    def dns_state():
        return {key: subprocess.check_output(["resolvectl", key, "corp0"], text=True).strip()
                for key in ("dns", "domain", "default-route")}

    def vpn_names():
        code = "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:18080/dns-observations').read().decode())"
        return json.loads(subprocess.check_output(["ip", "netns", "exec", "split-vpn", "python3", "-c", code], text=True)) or []

    def direct_names():
        return (temporary / "direct-dns.log").read_text().splitlines()

    def message(kind, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not select.select([child.stdout], [], [], 0.2)[0]:
                continue
            data = child.stdout.readline()
            assert data, "capture helper exited"
            row = json.loads(data)
            if row.get("type") == kind:
                return row
            assert row.get("type") != "error", row
        raise AssertionError("capture helper did not emit " + kind)

    def start(profile):
        nonlocal child
        child = subprocess.Popen([str(args.helper), "--cache-dir", str(temporary / "cache")],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        child.stdin.write(json.dumps(profile) + "\n")
        child.stdin.flush()
        message("ready")
        run("resolvectl", "flush-caches")

    def stop():
        nonlocal child
        if child is not None:
            if child.poll() is None:
                child.stdin.write("stop\n")
                child.stdin.flush()
            assert child.wait(timeout=15) == 0
            child = None

    def connect(name, marker, address=None):
        if address is None:
            address = socket.getaddrinfo(name, 18081, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            assert ipaddress.ip_address(address) in ipaddress.ip_network("198.18.0.0/15"), "OS DNS did not return FakeIP"
        with socket.create_connection((address, 18081), timeout=8) as client:
            assert client.recv(64).decode().strip() == marker, "wrong traffic observer for " + name
        return address

    try:
        network("split-corp", "corp0", "10.88.0.1", "10.88.0.53")
        network("split-vpn", "wan0", "198.51.100.1", "198.51.100.2")
        # Linux performs an initial route lookup before the OUTPUT capture
        # hook. A synthetic default route keeps this offline fixture realistic.
        run("ip", "route", "add", "default", "via", "198.51.100.2", "dev", "wan0")
        Path("/run/dbus").mkdir(parents=True, exist_ok=True)
        processes.append(subprocess.Popen(["dbus-daemon", "--system", "--nofork", "--nopidfile"]))
        deadline = time.monotonic() + 5
        while not Path("/run/dbus/system_bus_socket").exists():
            assert time.monotonic() < deadline
            time.sleep(0.05)
        resolver_user = pwd.getpwnam("systemd-resolve")
        Path("/run/systemd/resolve").mkdir(parents=True, exist_ok=True)
        os.chown("/run/systemd/resolve", resolver_user.pw_uid, resolver_user.pw_gid)
        Path("/etc/systemd/resolved.conf").write_text("[Resolve]\nDNSOverTLS=yes\n")
        processes.append(subprocess.Popen(["/usr/lib/systemd/systemd-resolved"], stdout=subprocess.DEVNULL))
        for attempt in range(100):
            result = subprocess.run(["resolvectl", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("systemd-resolved did not start")
        Path("/etc/resolv.conf").write_text("nameserver 127.0.0.53\nsearch corp.example\n")
        run("resolvectl", "dns", "corp0", "10.88.0.53")
        run("resolvectl", "dnsovertls", "corp0", "no")
        run("resolvectl", "domain", "corp0", "corp.example")
        run("resolvectl", "default-route", "corp0", "yes" if automatic else "no")
        log = temporary / "direct-dns.log"
        log.touch()
        observer = subprocess.Popen(["ip", "netns", "exec", "split-corp", "python3", "-u", str(script), "--observer", str(log)], stdout=subprocess.PIPE, text=True)
        processes.append(observer)
        assert observer.stdout.readline().strip() == "READY"
        assert socket.gethostbyname("before.corp.example") == "10.88.0.53"
        before = dns_state()
        fixture = temporary / "fixture.json"
        peer = subprocess.Popen(["ip", "netns", "exec", "split-vpn", str(args.peer), "--transport", args.transport,
                                 "--shared-ip", "198.51.100.2", "--bind-ip", "198.51.100.2", "--record-dns", "--persistent", "--config", str(fixture)],
                                stdout=subprocess.PIPE, text=True)
        processes.append(peer)
        assert peer.stdout.readline().startswith("READY")
        profile = json.loads(fixture.read_text())
        profile["sing_box_routing"] = {"version": 1, "default": "vpn", "rules": [
            {"kind": "domain", "value": "public.corp.example", "action": "vpn"},
            {"kind": "suffix", "value": "direct.test", "action": "direct"},
            {"kind": "suffix", "value": "corp.example", "action": "direct"}]}
        profile["sing_box_dns"] = {"version": 1, "default": "vpn", "follow_routing": True,
            "direct": "direct", "vpn": "vpn", "preserve_network_domains": True,
            "policies": {"direct": {"source": "network", "interface": "corp0", "transport": "udp", "server": "", "path": "direct"},
                         "vpn": {"transport": "udp", "server": "10.77.0.2", "path": "vpn"}},
            "rules": [{"kind": "domain", "value": "public.corp.example", "policy": "vpn"}]}
        if automatic:
            profile["sing_box_routing"] = automatic["initial"]["routing"]
            profile["sing_box_dns"] = automatic["initial"]["dns"]
            assert profile["sing_box_dns"]["rules"] == []
            assert not profile["sing_box_dns"].get("preserve_network_domains", False)
        start(profile)
        cached = connect("cached.corp.example", "DIRECT")
        connect("flow.direct.test", "DIRECT")
        connect("public.corp.example", "VPN")
        connect("ordinary.test", "VPN")
        assert dns_state() == before, "VPN overwrote corporate link settings"
        direct, vpn = direct_names(), vpn_names()
        assert "cached.corp.example." in direct and "public.corp.example." in vpn and "ordinary.test." in vpn
        assert "flow.direct.test." in direct and "flow.direct.test." not in vpn
        assert "public.corp.example." not in direct and "ordinary.test." not in direct
        assert "cached.corp.example." not in vpn
        report["simultaneous_dns_observers"] = {"direct": direct, "vpn": vpn}
        stop()
        assert dns_state() == before
        assert socket.gethostbyname("after.corp.example") == "10.88.0.53"
        # An application-cached FakeIP must retain its name across reconnect,
        # but must use the new DNS policy and a fresh real-address cache.
        if automatic:
            profile["sing_box_routing"] = automatic["reconnected"]["routing"]
            profile["sing_box_dns"] = automatic["reconnected"]["dns"]
        else:
            profile["sing_box_dns"]["rules"].append({"kind": "domain", "value": "cached.corp.example", "policy": "vpn"})
            profile["sing_box_routing"]["rules"].insert(0, {"kind": "domain", "value": "cached.corp.example", "action": "vpn"})
        start(profile)
        connect("cached.corp.example", "VPN", cached)
        assert "cached.corp.example." in vpn_names()
        report["cached_fakeip_reconnect_new_policy"] = "PASS"
        if automatic:
            report["qt_default_policy_and_native_domains_do_not_override_site_routes"] = "PASS"
        # DNS changes retire resolver work while retaining the TCP owner.
        retained_address = connect("retained.corp.example", "DIRECT")
        with socket.create_connection((retained_address, 18081), timeout=8) as retained, \
                socket.create_connection((cached, 18081), timeout=8) as retained_vpn:
            assert retained.recv(64) == b"DIRECT\n"
            assert retained_vpn.recv(64) == b"VPN\n"
            run("resolvectl", "dns", "corp0", "10.88.0.54")
            # The inventory watcher reconciles once per second in addition to
            # D-Bus signals. Allow it to observe the deliberately dead resolver.
            time.sleep(2)
            assert child.poll() is None, "DNS change stopped the TCP owner"
            for connection in (retained, retained_vpn):
                connection.sendall(b"during-dns-outage")
                assert connection.recv(64) == b"during-dns-outage"
            from run_linux_acceptance import resolve
            unavailable = "unavailable-after-change.corp.example"
            try:
                connect(unavailable, "DIRECT", resolve(unavailable))
            except OSError:
                pass
            else:
                raise AssertionError("unavailable network DNS unexpectedly resolved")
            assert unavailable + "." not in direct_names(), "retired resolver was reused"
            assert unavailable + "." not in vpn_names(), "network DNS leaked to VPN resolver"
            run("resolvectl", "dns", "corp0", "10.88.0.53")
            deadline = time.monotonic() + 20
            while True:
                try:
                    connect("recovered.corp.example", "DIRECT")
                    break
                except OSError:
                    assert time.monotonic() < deadline, "network DNS did not recover"
                    time.sleep(0.2)
            assert child.poll() is None
            for connection in (retained, retained_vpn):
                connection.sendall(b"after-dns-recovery")
                assert connection.recv(64) == b"after-dns-recovery"
        report["dns_change_retains_original_tcp"] = {"direct": "PASS", "vpn": "PASS"}
        stop()
        assert dns_state() == before
        # Native encrypted DNS must never reach the plaintext observer, even
        # when the TLS endpoint is unavailable. Exercise both network-source
        # selection and the automatically imported corporate-domain policy.
        run("resolvectl", "dns", "corp0", "10.88.0.53:8853#dns.corp.example")
        for mode in ("yes", "", "opportunistic"):
            run("resolvectl", "dnsovertls", "corp0", mode)
            start(profile)
            assert subprocess.check_output(["resolvectl", "dnsovertls", "amnrouting0"], text=True).strip().endswith("no")
            for suffix in ("corp.example", "direct.test"):
                name = "tls-" + (mode or "inherited") + "." + suffix
                # Query managed DNS directly: resolved's corporate rule could
                # otherwise choose its own TLS client before entering our TUN.
                from run_linux_acceptance import resolve
                address = resolve(name)
                try:
                    connect(name, "DIRECT", address)
                except OSError:
                    pass
                else:
                    raise AssertionError("unavailable TLS DNS unexpectedly resolved " + name)
                assert name + "." not in direct_names(), "native DoT silently downgraded to plaintext"
                assert name + "." not in vpn_names(), "native DoT crossed policy boundaries"
            stop()
        # An untrusted certificate is valid only in native opportunistic mode.
        # The real helper serializes the desktop snapshot before core startup.
        cert, key = temporary / "dns-cert.pem", temporary / "dns-key.pem"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=dns.corp.example", "-addext", "subjectAltName=DNS:dns.corp.example",
            "-keyout", key, "-out", cert, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls_log = temporary / "tls-dns.log"
        tls_log.touch()
        encrypted = subprocess.Popen(["ip", "netns", "exec", "split-corp", "python3", "-u", str(script),
                                      "--tls-observer", str(tls_log), str(cert), str(key)], stdout=subprocess.PIPE, text=True)
        processes.append(encrypted)
        assert encrypted.stdout.readline().strip() == "READY"
        for mode in ("opportunistic", "yes"):
            run("resolvectl", "dnsovertls", "corp0", mode)
            start(profile)
            for suffix in ("corp.example", "direct.test"):
                name = "selfsigned-" + mode + "." + suffix
                address = resolve(name)
                if mode == "opportunistic":
                    connect(name, "DIRECT", address)
                    assert name + "." in tls_log.read_text().splitlines(), "query did not reach TLS observer"
                else:
                    try:
                        connect(name, "DIRECT", address)
                    except OSError:
                        pass
                    else:
                        raise AssertionError("strict TLS accepted an untrusted certificate")
                    assert name + "." not in tls_log.read_text().splitlines(), "strict TLS sent DNS before authenticating"
                assert name + "." not in direct_names(), "TLS policy downgraded to plaintext"
                assert name + "." not in vpn_names(), "TLS policy crossed routing boundary"
            stop()
        run("resolvectl", "dnsovertls", "corp0", "no")
        run("resolvectl", "dns", "corp0", "10.88.0.53")
        assert dns_state() == before
        report["native_dot_no_plaintext_downgrade"] = "PASS"
        report["opportunistic_tls_through_serialized_session"] = "PASS"
        report["strict_tls_rejects_untrusted_certificate"] = "PASS"
        report.update(split_dns="PASS", corporate_systemd_resolved="PASS", network_dns_change="PASS", dns_restoration="PASS")
    finally:
        if child is not None:
            child.kill()
            child.wait(timeout=5)
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for namespace in reversed(namespaces):
            subprocess.run(["ip", "netns", "del", namespace], check=False)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--observer":
        dns_observer(Path(sys.argv[2]))
    elif len(sys.argv) == 5 and sys.argv[1] == "--tls-observer":
        tls_observer(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        main()
