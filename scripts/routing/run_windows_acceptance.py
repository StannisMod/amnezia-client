#!/usr/bin/env python3
"""Actual Windows Wintun capture on a disposable elevated CI/VM host.

The host's network is temporarily captured; always close the helper in finally.
No user/server profile or public release is used or changed.
"""
import argparse
import ctypes
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time

from run_linux_acceptance import probe, resolve, tcp, udp


def powershell(command):
    return subprocess.check_output(["powershell", "-NoProfile", "-Command", command], text=True).strip()


def network_state():
    # Compare unrelated routes/DNS separately from timestamps and counters.
    routes = json.loads(powershell("@(Get-NetRoute | Where-Object {$_.InterfaceAlias -ne 'AmneziaDomainRouting'} | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore) | ConvertTo-Json -Depth 5 -Compress"))
    dns = json.loads(powershell("@(Get-DnsClientServerAddress | Where-Object {$_.InterfaceAlias -ne 'AmneziaDomainRouting'} | Select-Object InterfaceIndex,AddressFamily,ServerAddresses) | ConvertTo-Json -Depth 5 -Compress"))
    return {"routes": sorted(routes, key=lambda row: json.dumps(row, sort_keys=True)), "dns": sorted(dns, key=lambda row: json.dumps(row, sort_keys=True))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=100)
    args = parser.parse_args()
    assert os.name == "nt" and ctypes.windll.shell32.IsUserAnAdmin(), "an elevated disposable Windows host is required"
    assert 1 <= args.cycles <= 1000
    report = {"native_capture": "FAIL", "not_run": ["installed Qt service", "EXE/MSI installation", "physical machine", "Wi-Fi/Ethernet handover", "OS kill switch", "per-app routing", "BFE restart/boot-time protection"]}
    helper = args.helper.resolve(); peer = child = None
    messages = queue.Queue()
    def control(path, post=False):
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
        connection.request("POST" if post else "GET", path)
        response = connection.getresponse(); data = response.read(); connection.close()
        assert response.status == 200
        return None if post else json.loads(data)
    def stop():
        nonlocal child
        if child is not None:
            if child.poll() is None:
                child.stdin.write("stop\n"); child.stdin.flush()
            assert child.wait(timeout=20) == 0
            child = None
    temporary = tempfile.TemporaryDirectory()
    cache = Path(temporary.name) / "private-cache"
    def native_udp():
        # No public service response is required: an ordinary outbound UDP
        # send is permitted before capture/recovery and denied by WFP after
        # the helper is forcibly killed. The destination is not loopback.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            return sock.sendto(b"amnezia-routing-guard-probe", ("1.1.1.1", 9))
    try:
        assert native_udp() > 0
        # Existing native local IPv4 is reachable outside the captured adapter.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as selection:
            selection.connect(("1.1.1.1", 53)); shared = selection.getsockname()[0]
        assert ipaddress.ip_address(shared).version == 4 and not ipaddress.ip_address(shared).is_loopback
        before = network_state()
        directory = temporary.name
        fixture = Path(directory) / "fixture.json"
        peer = subprocess.Popen([str(args.peer.resolve()), "--shared-ip", shared, "--config", str(fixture)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(peer.stdout.readline()), daemon=True).start()
        assert ready.get(timeout=15).startswith("READY"), "AWG fixture failed to start"
        profile = json.loads(fixture.read_text())
        profile["sing_box_routing"] = {"version": 1, "default": "vpn", "rules": [
            {"kind": "suffix", "value": "direct.ru", "action": "direct"},
            {"kind": "domain", "value": "vpn.test", "action": "vpn"},
        ]}
        cache = Path(directory) / "private-cache"
        def start(inverse=False):
            nonlocal child, messages
            profile["sing_box_routing"]["default"] = "direct" if inverse else "vpn"
            messages = queue.Queue()
            child = subprocess.Popen([str(helper), "--cache-dir", str(cache)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            def read(stream, destination):
                for line in stream:
                    destination.put(json.loads(line))
                destination.put({"type": "exited"})
            threading.Thread(target=read, args=(child.stdout, messages), daemon=True).start()
            child.stdin.write(json.dumps(profile) + "\n"); child.stdin.flush()
            end = time.monotonic() + 30
            while time.monotonic() < end:
                row = messages.get(timeout=30)
                assert row.get("type") not in ("error", "exited"), row.get("message", "helper exited")
                if row.get("type") == "connected":
                    return
            raise AssertionError("Windows helper did not establish AWG")
        start()
        direct, vpn = resolve("direct.ru"), resolve("vpn.test")
        assert direct != vpn
        probe({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1], ["shop.direct.ru", "DIRECT", 1], ["notdirect.ru.test", "VPN", 1], ["cname.test", "VPN", 1], ["ipv6.test", "VPN", 28]], "loopback": ["127.0.0.1", "::1"]})
        # Query through Windows' configured system resolver as well as the
        # explicit UDP capture address used by the shared probes.
        system = socket.getaddrinfo("system.direct.ru", 18081, socket.AF_INET, socket.SOCK_STREAM)
        assert system and all(ipaddress.ip_address(row[4][0]) in ipaddress.ip_network("198.18.0.0/15") for row in system)
        assert tcp(system[0][4][0]) == "DIRECT"
        counts = control("/stats"); control("/peer?state=off", True)
        for request in (tcp, udp):
            try:
                request(vpn)
            except OSError:
                pass
            else:
                raise AssertionError("VPN flow escaped after AWG loss")
        after = control("/stats")
        assert counts["direct_tcp"] == after["direct_tcp"] and counts["direct_udp"] == after["direct_udp"]
        control("/peer?state=on", True)
        stop(); start(True)
        probe({"names": [["unlisted.test", "DIRECT", 1], ["vpn.test", "VPN", 1]]})
        assert resolve("vpn.test") == vpn
        for cycle in range(args.cycles):
            stop(); start(bool(cycle & 1))
            assert tcp(resolve("vpn.test")) == "VPN"
            if (cycle + 1) % 10 == 0:
                print("PASS reconnect cycles:", cycle + 1, flush=True)
        child.kill(); child.wait(timeout=20); child = None
        # Wait for the last Wintun handle to disappear. The separately owned
        # crash policy must remain after the captured adapter is gone.
        for _ in range(30):
            if powershell("@(Get-NetAdapter -IncludeHidden | Where-Object Name -eq 'AmneziaDomainRouting').Count") == "0":
                break
            time.sleep(0.2)
        else:
            raise AssertionError("crashed Wintun adapter did not disappear")
        for _ in range(3):
            try:
                native_udp()
            except OSError as error:
                assert error.winerror == 10013, f"expected WFP access denial, got {error}"
            else:
                raise AssertionError("native traffic escaped after helper crash")
        # A new start must not silently discard the stale crash guard.
        stale = subprocess.Popen([str(helper), "--cache-dir", str(cache)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, _ = stale.communicate(json.dumps(profile) + "\n", timeout=20)
        assert any(json.loads(line).get("type") == "error" for line in output.splitlines()), "stale guard was silently replaced"
        try:
            native_udp()
        except OSError as error:
            assert error.winerror == 10013
        else:
            raise AssertionError("rejected restart removed crash protection")
        subprocess.run([str(helper), "--cache-dir", str(cache), "--recover"], check=True, timeout=20)
        assert native_udp() > 0
        start(); assert tcp(resolve("vpn.test")) == "VPN"
        stop()
        subprocess.run([str(helper), "--cache-dir", str(cache), "--recover"], check=True)
        # Give Windows' adapter-removal notification a bounded settling period.
        for _ in range(30):
            after = network_state()
            if after == before:
                break
            time.sleep(0.2)
        assert after == before, "native routes/DNS did not return to their original state"
        report.update(native_capture="PASS", reconnect_cycles=args.cycles, os_state_restored=True, helper_crash_fail_closed=True,
                      scenarios=["actual Wintun/gVisor capture", "same-IP domain identity", "native DIRECT and AWG TCP/UDP", "IPv6", "system DNS/FakeIP", "CNAME", "suffix boundaries", "loopback", "AWG loss fails closed", "inverse mode", "FakeIP persistence", "forced helper termination retains WFP guard", "stale guard rejects restart", "explicit recovery permits native traffic and reconnect"])
    finally:
        try:
            report["diagnostics"] = {
                "routes": powershell("Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric | ConvertTo-Json -Compress"),
                "observers": control("/stats"),
            }
        except Exception:
            pass
        if child is not None:
            try:
                stop()
            except Exception:
                child.kill(); child.wait(timeout=15)
        if peer is not None:
            peer.terminate(); peer.wait(timeout=15)
        subprocess.run([str(helper), "--cache-dir", str(cache), "--recover"], timeout=20, check=True)
        temporary.cleanup()
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
