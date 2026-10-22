#!/usr/bin/env python3
"""Real Linux TUN/policy tests confined to a disposable network namespace.

This does not claim installed Qt-service, systemd-resolved or installer proof.
"""
import argparse
import difflib
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
    with socket.create_connection((address, 18081), timeout=10) as client:
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
            if options.get("other_process"):
                other = options["other_expected"]
                for protocol, port, marker in (("tcp", 18081, other), ("udp", 18082, other + ":proof")):
                    destination = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
                    output = subprocess.check_output([options["other_process"], "--probe-" + protocol, destination], text=True, timeout=15)
                    assert output.strip() == marker, "wrong observer for independent executable"
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
    for name, expected, kind in options.get("quic_names", []):
        address = resolve(name, kind)
        destination = f"[{address}]:18443" if ":" in address else f"{address}:18443"
        output = subprocess.check_output([options["quic_probe"], "--quic", destination, "--ca", options["quic_ca"]], text=True, timeout=20)
        assert output.strip() == expected, "wrong native QUIC observer"
        print(f"PASS native QUIC/TLS digest: {name} -> {expected}", file=sys.stderr, flush=True)
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
    parser.add_argument("--quic-probe", type=Path, required=True)
    args = parser.parse_args()
    ns = "amnezia-routing-test"
    host = "amnrtest-host"
    backup = "amnrtest-backup"
    helper = args.helper.resolve(); script = Path(__file__).resolve()
    child = peer = None
    headers = None
    observer_owned = False
    observer = "198.51.100.2"
    child_buffer = b""
    report = {"native_capture": "FAIL", "not_run": ["installed Qt service", "systemd-resolved integration", "installer", "OS kill switch", "physical Wi-Fi/Ethernet handover", "GUI network-change callback"]}
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
        raise AssertionError("routing helper did not emit " + kind)
    def stop():
        nonlocal child
        if child is not None:
            if child.poll() is None:
                child.stdin.write("stop\n"); child.stdin.flush()
            assert child.wait(timeout=15) == 0
            child = None
    try:
        ip("addr", "add", observer + "/32", "dev", "lo")
        observer_owned = True
        ip("netns", "add", ns)
        ip("link", "add", host, "type", "veth", "peer", "name", "eth0", "netns", ns)
        ip("addr", "add", "10.0.2.2/24", "dev", host)
        ip("addr", "add", "203.0.113.20/32", "dev", host)
        ip("link", "set", host, "up")
        ns_ip("link", "set", "lo", "up")
        ns_ip("addr", "add", "10.0.2.15/24", "dev", "eth0")
        ns_ip("link", "set", "eth0", "up")
        ip("link", "add", backup, "type", "veth", "peer", "name", "eth1", "netns", ns)
        ip("addr", "add", "10.0.3.2/24", "dev", backup)
        ip("link", "set", backup, "up")
        ns_ip("addr", "add", "10.0.3.15/24", "dev", "eth1")
        ns_ip("link", "set", "eth1", "up")
        # IPv6 DAD adds the namespace's native link-local route asynchronously.
        # Snapshot the native baseline after it settles, so normal kernel
        # initialization is not misreported as a VPN cleanup change.
        for _ in range(50):
            native_ipv6 = ns_ip("-6", "addr", "show")
            if "scope link" in native_ipv6 and "tentative" not in native_ipv6:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("native IPv6 address initialization did not settle")
        ns_ip("route", "add", "default", "via", "10.0.2.2")
        ns_ip("route", "add", "203.0.113.0/24", "via", "10.0.2.2", "table", "222")
        ns_ip("rule", "add", "pref", "100", "to", "203.0.113.0/24", "lookup", "222")
        for interface in ("eth0", "eth1"):
            run("ip", "netns", "exec", ns, "sysctl", "-qw", f"net.ipv4.conf.{interface}.rp_filter=1")
        before_rpf = {interface: run("ip", "netns", "exec", ns, "sysctl", "-n", f"net.ipv4.conf.{interface}.rp_filter", capture_output=True, text=True).stdout for interface in ("eth0", "eth1")}
        before_nft = run("ip", "netns", "exec", ns, "nft", "list", "tables", capture_output=True, text=True).stdout
        before_rules = ns_ip("rule", "show")
        before_routes = ns_ip("route", "show", "table", "all")
        report["native_routes_before"] = before_routes
        ca = args.fixture.with_suffix(".quic.der")
        peer = subprocess.Popen([str(args.peer.resolve()), "--shared-ip", observer, "--config", str(args.fixture), "--quic-ca", str(ca)], stdout=subprocess.PIPE, text=True)
        assert select.select([peer.stdout], [], [], 10)[0] and peer.stdout.readline().startswith("READY")
        profile = json.loads(args.fixture.read_text())
        application({"direct": [observer]})
        report["native_underlay_before_capture"] = "PASS"
        outer = run("ip", "netns", "exec", ns, str(args.peer.resolve()), "--probe-awg", str(args.fixture.resolve()), capture_output=True, text=True, timeout=25)
        assert outer.stdout.strip() == "VPN", "AWG underlay observer was not reached before capture"
        report["awg_underlay_before_capture"] = "PASS"
        # Header-only diagnostics for this disposable fixture port. Never log
        # payloads, encrypted datagrams, credentials or unrelated host traffic.
        headers = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        headers.settimeout(0.2)
        report["fixture_udp_headers"] = []
        def record_headers():
            while headers.fileno() >= 0:
                try:
                    packet, address = headers.recvfrom(60)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if len(packet) < 28 or packet[9] != 17:
                    continue
                offset = (packet[0] & 15) * 4
                if len(packet) < offset + 8:
                    continue
                source, destination, size = struct.unpack_from("!HHH", packet, offset)
                if profile["awg_config_data"]["port"] not in (source, destination):
                    continue
                if len(report["fixture_udp_headers"]) < 60:
                    report["fixture_udp_headers"].append({"interface": address[0], "source": socket.inet_ntoa(packet[12:16]), "destination": socket.inet_ntoa(packet[16:20]), "source_port": source, "destination_port": destination, "udp_length": size})
        threading.Thread(target=record_headers, daemon=True).start()
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
            application({"quic_probe":str(args.quic_probe.resolve()), "quic_ca":str(ca), "quic_names":[["direct.ru","DIRECT",1],["vpn.test","VPN",1],["ipv6.test","VPN",28]]})
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
            # Distinct Python/Go executables share identical destinations but
            # must follow their application scope before domain routing.
            for mode, selected, other in ((2, "DIRECT", "VPN"), (1, "VPN", "DIRECT")):
                stop()
                profile["appSplitTunnelType"] = mode
                profile["splitTunnelApps"] = [str(Path(sys.executable).resolve())]
                start()
                application({"names": [["vpn.test", selected, 1]], "other_process": str(args.peer.resolve()), "other_expected": other})
                application({"names": [["direct.ru", "DIRECT", 1]]})
            stop(); profile.pop("appSplitTunnelType"); profile.pop("splitTunnelApps"); start()
            # Move the real underlay, then recreate the session as native
            # host network-change callbacks do. Transport/DNS sockets must not
            # retain the old interface. This tests virtual NIC failover and
            # session recovery, not GUI callbacks or physical Wi-Fi hardware.
            active_pid = child.pid
            ns_ip("route", "replace", "default", "via", "10.0.3.2", "dev", "eth1")
            ns_ip("link", "set", "eth0", "down")
            decision = ns_ip("route", "get", observer, "mark", "0x40000000")
            assert "dev eth1" in decision and "src 10.0.3.15" in decision, decision
            physical_probe = "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x40000000); s.settimeout(5); s.connect(('198.51.100.2',18081)); assert s.recv(32).strip()==b'DIRECT'; s.close()"
            run("ip", "netns", "exec", ns, sys.executable, "-c", physical_probe)
            report["backup_underlay_observer_reachable"] = True
            stop(); start()
            application({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1]]})
            assert child.pid != active_pid and child.poll() is None
            # With no live uplink, assigned VPN traffic must not escape DIRECT.
            ns_ip("link", "set", "eth1", "down")
            counts_before_loss = control("/stats")
            application({"blocked": [identities["vpn.test"]]})
            counts_after_loss = control("/stats")
            assert counts_after_loss["direct_tcp"] == counts_before_loss["direct_tcp"]
            assert counts_after_loss["direct_udp"] == counts_before_loss["direct_udp"]
            ns_ip("link", "set", "eth0", "up")
            ns_ip("route", "replace", "default", "via", "10.0.2.2", "dev", "eth0")
            ns_ip("link", "set", "eth1", "up")
            stop(); start()
            application({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1]]})
            for _ in range(50):
                if "tentative" not in ns_ip("-6", "addr", "show"):
                    break
                time.sleep(0.1)
            report["virtual_uplink_failover"] = "PASS"
            report["uplink_loss_fail_closed_and_recovery"] = "PASS"
            for cycle in range(args.cycles):
                stop(); start(bool(cycle & 1))
                application({"names": [["vpn.test", "VPN", 1]]})
            # Unexpected service command-pipe loss is not an explicit stop.
            child.stdin.close(); assert child.wait(timeout=15) == 0; child = None
            application({"blocked": ["10.0.2.2"]})
            run("ip", "netns", "exec", ns, helper, "--cache-dir", directory, "--recover")
            start()
            # A killed Go process must leave the capture policy failing closed
            # until an explicit service recovery, rather than release packets.
            child.kill(); child.wait(timeout=10); child = None
            before = control("/stats")
            application({"blocked": ["10.0.2.2"]})
            after = control("/stats")
            assert before["direct_tcp"] == after["direct_tcp"] and before["direct_udp"] == after["direct_udp"]
            # A foreign modification must prevent recovery rather than be erased.
            run("ip", "netns", "exec", ns, "nft", "add", "chain", "inet", "amnezia_route_capture", "foreign")
            occupied = ns_ip("rule", "show")
            refused = subprocess.run(["ip", "netns", "exec", ns, str(helper), "--cache-dir", directory, "--recover"], capture_output=True, text=True, timeout=10)
            assert refused.returncode != 0 and "unrecognized packet marking chain" in refused.stderr
            assert ns_ip("rule", "show") == occupied, "refused recovery changed policy rules"
            run("ip", "netns", "exec", ns, "nft", "delete", "chain", "inet", "amnezia_route_capture", "foreign")
            run("ip", "netns", "exec", ns, helper, "--cache-dir", directory, "--recover")
            report["foreign_nft_state_preserved"] = "PASS"
        assert run("ip", "netns", "exec", ns, "nft", "list", "tables", capture_output=True, text=True).stdout == before_nft
        for interface, value in before_rpf.items():
            assert run("ip", "netns", "exec", ns, "sysctl", "-n", f"net.ipv4.conf.{interface}.rp_filter", capture_output=True, text=True).stdout == value
        report["off_link_peer_with_strict_physical_rpf"] = "PASS"
        assert ns_ip("rule", "show") == before_rules
        restored_routes = ns_ip("route", "show", "table", "all")
        assert restored_routes == before_routes, "native route restoration differs:\n" + "".join(difflib.unified_diff(before_routes.splitlines(True), restored_routes.splitlines(True), fromfile="before", tofile="after"))
        report.update(native_capture="PASS", scenarios=["FakeIP identity/shared real IP", "DIRECT and AWG TCP/UDP", "IPv6", "CNAME", "native policy route", "loopback IPv4/IPv6", "inverse mode", "persistent FakeIP", "application include/exclude with independent executables and domain precedence", "AWG loss fails closed", "helper crash fails closed and explicit recovery"], reconnect_cycles=args.cycles, os_state_restored=True)
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
                "capture_marking": run("ip", "netns", "exec", ns, "nft", "list", "tables", capture_output=True, text=True).stdout,
                "host_routes": ip("route", "get", "10.0.2.15"),
                "host_links": ip("-s", "link", "show", host),
                "observers": control("/stats"),
            }
        except Exception:
            pass
        if child is not None:
            child.kill(); child.wait(timeout=10)
        if headers is not None:
            headers.close()
        if peer is not None:
            peer.terminate(); peer.wait(timeout=10)
        if observer_owned:
            subprocess.run(["ip", "addr", "del", observer + "/32", "dev", "lo"], capture_output=True)
        subprocess.run(["ip", "link", "del", backup], capture_output=True)
        subprocess.run(["ip", "link", "del", host], capture_output=True)
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
        args.fixture.unlink(missing_ok=True)
        args.fixture.with_suffix(".quic.der").unlink(missing_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--probe":
        probe(json.loads(sys.argv[2]))
    else:
        main()
