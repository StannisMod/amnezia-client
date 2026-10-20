#!/usr/bin/env python3
"""Real Linux TUN/policy tests confined to a disposable network namespace.

This does not claim installed Qt-service, systemd-resolved or installer proof.
"""
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def skip_name(data, offset):
    while data[offset]:
        if data[offset] & 192 == 192:
            return offset + 2
        offset += 1 + data[offset]
    return offset + 1


def resolve(name, kind=1):
    query = struct.pack("!6H", 77, 0x100, 1, 0, 0, 0)
    query += b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0" + struct.pack("!HH", kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(4)
        client.sendto(query, ("172.19.0.2", 53))
        answer = client.recv(4096)
    assert struct.unpack_from("!HH", answer)[0] == 77 and struct.unpack_from("!H", answer, 2)[0] & 0x800F == 0x8000
    offset = skip_name(answer, 12) + 4
    for _ in range(struct.unpack_from("!H", answer, 6)[0]):
        offset = skip_name(answer, offset)
        rrtype, _, _, length = struct.unpack_from("!HHIH", answer, offset)
        offset += 10
        if rrtype == kind:
            address = ipaddress.ip_address(answer[offset:offset + length])
            assert address in ipaddress.ip_network("198.18.0.0/15" if kind == 1 else "fc00::/18")
            return str(address)
        offset += length
    raise AssertionError("managed DNS did not return the expected FakeIP")


def tcp(address):
    with socket.create_connection((address, 18081), timeout=3) as client:
        return client.recv(32).decode().strip()


def udp(address):
    with socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(b"proof", (address, 18082))
        return client.recv(32).decode()


def probe(options):
    results = {}
    for name, expected, kind in options.get("names", []):
        print(f"CHECK {name}: {expected}, DNS type {kind}", file=sys.stderr, flush=True)
        address = resolve(name, kind)
        try:
            assert tcp(address) == expected, "wrong TCP observer"
            assert udp(address) == expected + ":proof", "wrong UDP observer"
        except Exception as error:
            raise AssertionError(f"{name}: expected {expected} over IPv{ipaddress.ip_address(address).version}: {error}") from error
        results[name] = address
        print(f"PASS {name}: TCP/UDP over IPv{ipaddress.ip_address(address).version}", file=sys.stderr, flush=True)
    for address in options.get("blocked", []):
        for request in (tcp, udp):
            try:
                request(address)
            except OSError:
                continue
            raise AssertionError("traffic reached an observer while the assigned VPN was unavailable")
    for address in options.get("direct", []):
        assert tcp(address) == "DIRECT" and udp(address) == "DIRECT:proof"
    for ip in options.get("loopback", []):
        with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET) as listener:
            listener.bind((ip, 0)); listener.listen(); listener.settimeout(3)
            def serve():
                peer, _ = listener.accept()
                with peer: peer.sendall(b"LOCAL")
            worker = threading.Thread(target=serve); worker.start()
            with socket.create_connection((ip, listener.getsockname()[1]), timeout=3) as client:
                assert client.recv(16) == b"LOCAL"
            worker.join(4); assert not worker.is_alive()
    print(json.dumps(results))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=100)
    args = parser.parse_args()
    ns = "amnezia-routing-test"
    host = "amnrtest-host"
    helper = args.helper.resolve(); script = Path(__file__).resolve()
    child = peer = None
    child_buffer = b""
    report = {"native_capture": "FAIL", "not_run": ["installed Qt service", "systemd-resolved integration", "installer", "OS kill switch", "application rules", "network handover"]}
    def ip(*parts):
        return run("ip", *parts, capture_output=True, text=True).stdout
    def ns_ip(*parts):
        return ip("-n", ns, *parts)
    def application(options):
        result = subprocess.run(["ip", "netns", "exec", ns, sys.executable, str(script), "--probe", json.dumps(options)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    def control(path, post=False):
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
        connection.request("POST" if post else "GET", path)
        response = connection.getresponse(); data = response.read(); connection.close()
        assert response.status == 200
        return None if post else json.loads(data)
    def await_message(kind):
        nonlocal child_buffer
        end = time.monotonic() + 20
        while time.monotonic() < end:
            if b"\n" not in child_buffer:
                if not select.select([child.stdout], [], [], 1)[0]:
                    continue
                data = os.read(child.stdout.fileno(), 8192)
                assert data, "routing helper exited during startup"
                child_buffer += data
                if b"\n" not in child_buffer:
                    continue
            line, child_buffer = child_buffer.split(b"\n", 1)
            row = json.loads(line)
            assert row.get("type") != "error", row.get("message")
            if row.get("type") == kind:
                return row
        raise AssertionError("routing helper did not become ready")
    def stop():
        nonlocal child
        if child is not None:
            if child.poll() is None:
                child.stdin.write("stop\n"); child.stdin.flush()
            assert child.wait(timeout=15) == 0
            child = None
    try:
        ip("netns", "add", ns)
        ip("link", "add", host, "type", "veth", "peer", "name", "eth0", "netns", ns)
        ip("addr", "add", "10.0.2.2/24", "dev", host)
        ip("addr", "add", "203.0.113.20/32", "dev", host)
        ip("link", "set", host, "up")
        ns_ip("link", "set", "lo", "up")
        ns_ip("addr", "add", "10.0.2.15/24", "dev", "eth0")
        ns_ip("link", "set", "eth0", "up")
        ns_ip("route", "add", "default", "via", "10.0.2.2")
        ns_ip("route", "add", "203.0.113.0/24", "via", "10.0.2.2", "table", "222")
        ns_ip("rule", "add", "pref", "100", "to", "203.0.113.0/24", "lookup", "222")
        before_rules = ns_ip("rule", "show")
        before_routes = ns_ip("route", "show", "table", "all")
        peer = subprocess.Popen([str(args.peer.resolve()), "--config", str(args.fixture)], stdout=subprocess.PIPE, text=True)
        assert select.select([peer.stdout], [], [], 10)[0] and peer.stdout.readline().startswith("READY")
        profile = json.loads(args.fixture.read_text())
        profile["sing_box_routing"] = {"version": 1, "default": "vpn", "rules": [
            {"kind": "suffix", "value": "direct.ru", "action": "direct"},
            {"kind": "domain", "value": "vpn.test", "action": "vpn"},
            {"kind": "cidr", "value": "203.0.113.0/24", "action": "direct"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            def start(inverse=False):
                nonlocal child, child_buffer
                child_buffer = b""
                profile["sing_box_routing"]["default"] = "direct" if inverse else "vpn"
                child = subprocess.Popen(["ip", "netns", "exec", ns, str(helper), "--no-system-dns", "--cache-dir", directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
                child.stdin.write(json.dumps(profile) + "\n"); child.stdin.flush()
                await_message("ready"); await_message("connected")
            # RuleList in the pinned netlink library does not populate its
            # MarkSet flag. A foreign policy using our bit must still block
            # startup, without modifying any existing native rule.
            ns_ip("rule", "add", "pref", "99", "fwmark", "0x40000000/0x40000000", "lookup", "main")
            occupied = ns_ip("rule", "show")
            refused = subprocess.run(["ip", "netns", "exec", ns, str(helper), "--no-system-dns", "--cache-dir", directory], input=json.dumps(profile) + "\n", capture_output=True, text=True, timeout=10)
            assert "native mark policy uses the reserved VPN exemption bit" in refused.stdout
            assert ns_ip("rule", "show") == occupied, "conflict rejection modified native policy"
            ns_ip("rule", "del", "pref", "99", "fwmark", "0x40000000/0x40000000", "lookup", "main")
            start()
            identities = application({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1], ["cname.test", "VPN", 1], ["ipv6.test", "VPN", 28]], "direct": ["203.0.113.20"], "loopback": ["127.0.0.1", "::1"]})
            assert identities["direct.ru"] != identities["vpn.test"]
            marked = ns_ip("route", "get", "203.0.113.20", "mark", "0x40000000")
            assert "table 222" in marked and "via 10.0.2.2" in marked, "DIRECT did not preserve the native policy rule"
            before = control("/stats"); control("/peer?state=off", True)
            application({"blocked": [identities["vpn.test"]]})
            after = control("/stats")
            assert before["direct_tcp"] == after["direct_tcp"] and before["direct_udp"] == after["direct_udp"]
            control("/peer?state=on", True)
            stop(); start(True)
            application({"names": [["unlisted.test", "DIRECT", 1], ["vpn.test", "VPN", 1]]})
            stop(); start()
            again = application({"names": [["vpn.test", "VPN", 1]]})
            assert again["vpn.test"] == identities["vpn.test"]
            for cycle in range(args.cycles):
                stop(); start(bool(cycle & 1))
                application({"names": [["vpn.test", "VPN", 1]]})
            # A killed Go process must leave the capture policy failing closed
            # until an explicit service recovery, rather than release packets.
            child.kill(); child.wait(timeout=10); child = None
            before = control("/stats")
            application({"blocked": ["10.0.2.2"]})
            after = control("/stats")
            assert before["direct_tcp"] == after["direct_tcp"] and before["direct_udp"] == after["direct_udp"]
            run("ip", "netns", "exec", ns, helper, "--cache-dir", directory, "--recover")
        assert ns_ip("rule", "show") == before_rules
        assert ns_ip("route", "show", "table", "all") == before_routes
        report.update(native_capture="PASS", scenarios=["FakeIP identity/shared real IP", "DIRECT and AWG TCP/UDP", "IPv6", "CNAME", "native policy route", "loopback IPv4/IPv6", "inverse mode", "persistent FakeIP", "AWG loss fails closed", "helper crash fails closed and explicit recovery"], reconnect_cycles=args.cycles, os_state_restored=True)
    finally:
        # This namespace contains only controlled fixture traffic. Record
        # interface counters and route decisions, never packet payloads/keys.
        try:
            report["diagnostics"] = {
                "rules": ns_ip("rule", "show"),
                "ipv6_rules": ns_ip("-6", "rule", "show"),
                "routes": ns_ip("route", "show", "table", "all"),
                "ipv6_routes": ns_ip("-6", "route", "show", "table", "all"),
                "links": ns_ip("-s", "link", "show"),
                "observers": control("/stats"),
            }
        except Exception:
            pass
        if child is not None:
            child.kill(); child.wait(timeout=10)
        if peer is not None:
            peer.terminate(); peer.wait(timeout=10)
        subprocess.run(["ip", "link", "del", host], capture_output=True)
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
        args.fixture.unlink(missing_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--probe":
        probe(json.loads(sys.argv[2]))
    else:
        main()
