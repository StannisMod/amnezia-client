#!/usr/bin/env python3
"""Installed Qt service/real resolver acceptance on disposable CI hosts only."""
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from run_linux_acceptance import probe, tcp, resolve


def command(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=30, **kwargs)


def ps(script):
    return subprocess.check_output(["powershell", "-NoProfile", "-Command", script], text=True, timeout=20).strip()


def native_connect():
    with socket.create_connection(("1.1.1.1", 443), timeout=5):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--qt-probe", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--resolver-cycles", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.resolver_cycles <= 100:
        parser.error("--resolver-cycles must be between 1 and 100")
    win = os.name == "nt"
    report = {"installed_service": "FAIL", "not_run": ["physical host", "full GUI interaction", "network handover", "performance parity"]}
    peer = stream = sock = None
    temporary = tempfile.TemporaryDirectory()
    events = queue.Queue()

    def toggle(enabled):
        command(args.qt_probe.resolve(), "on" if enabled else "off")

    def send(row):
        stream.write(json.dumps(row).encode() + b"\n"); stream.flush()

    def wait(kind, timeout=30):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            row = events.get(timeout=max(0.1, end - time.monotonic()))
            assert row.get("type") not in ("error", "backendFailure", "exited"), "installed service/child failed"
            if row.get("type") == kind:
                return row
        raise AssertionError("service response timed out: " + kind)

    def connect():
        send({"type": "activate", "routing_profile": profile})
        wait("connected")

    def disconnect():
        send({"type": "deactivate"}); wait("disconnected")
        send({"type": "status"}); assert not wait("status")["connected"]

    def observers():
        c = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
        c.request("GET", "/stats"); r = c.getresponse(); data = json.loads(r.read()); c.close()
        assert r.status == 200
        return data

    def open_channel():
        nonlocal stream, sock, events
        events = queue.Queue()
        if win:
            stream = open(r"\\.\pipe\amneziavpn", "r+b", buffering=0)
        else:
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(20); sock.connect("/var/run/amneziavpn/daemon.socket")
            sock.settimeout(None); stream = sock.makefile("rwb", buffering=0)
        def reader(source, destination):
            try:
                for line in source:
                    destination.put(json.loads(line))
            except (OSError, ValueError):
                pass
            destination.put({"type": "exited"})
        threading.Thread(target=reader, args=(stream, events), daemon=True).start()

    def close_channel():
        nonlocal stream, sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close(); sock = None
        if stream is not None:
            stream.close(); stream = None

    def resolver_diagnostics(include_query=True):
        if win:
            return {}
        result = {}
        for label, argv in (
            ("status", ["resolvectl", "status"]),
            ("query", ["resolvectl", "query", "--type=A", "service.direct.ru"]),
            ("rules", ["ip", "rule", "show"]),
            ("capture_routes", ["ip", "route", "show", "table", "20313"]),
        ):
            if label == "query" and not include_query:
                continue
            try:
                row = subprocess.run(argv, capture_output=True, text=True, timeout=15)
                result[label] = {"exit_code": row.returncode, "stdout": row.stdout, "stderr": row.stderr}
            except subprocess.TimeoutExpired:
                result[label] = {"timeout": True}
        for path in ("/etc/resolv.conf", "/etc/nsswitch.conf"):
            result[path] = {"target": str(Path(path).resolve()), "text": Path(path).read_text()}
        return result

    def snapshot():
        if win:
            from run_windows_acceptance import network_state
            return network_state()
        return {"routes4": subprocess.check_output(["ip", "-4", "route", "show", "table", "all"], text=True),
                "routes6": subprocess.check_output(["ip", "-6", "route", "show", "table", "all"], text=True),
                "dns": subprocess.check_output(["resolvectl", "dns"], text=True)}

    try:
        native_connect()
        if win:
            assert ps("(Get-Service -Name 'AmneziaVPN-service').Status") == "Running"
        else:
            command("systemctl", "is-active", "--quiet", "AmneziaVPN")
            command("systemctl", "is-active", "--quiet", "systemd-resolved")
        toggle(False)
        before = snapshot()
        report["resolver_before"] = resolver_diagnostics(include_query=False)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 53)); shared = s.getsockname()[0]
        fixture = Path(temporary.name) / "fixture.json"
        peer = subprocess.Popen([str(args.peer.resolve()), "--shared-ip", shared, "--config", str(fixture)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(peer.stdout.readline()), daemon=True).start()
        assert ready.get(timeout=20).startswith("READY"), "controlled peer failed"
        profile = json.loads(fixture.read_text())
        profile["killSwitchOption"] = "true"
        profile["sing_box_routing"] = {"version": 1, "default": "vpn", "rules": [
            {"kind": "suffix", "value": "direct.ru", "action": "direct"},
            {"kind": "domain", "value": "vpn.test", "action": "vpn"},
        ]}
        open_channel()
        connect()
        probe({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1], ["ipv6.test", "VPN", 28]], "loopback": ["127.0.0.1", "::1"]})
        # Go helper configures the actual OS resolver, including resolved's
        # per-link DNS on Linux. This uses the OS API, not an explicit DNS IP.
        rows = socket.getaddrinfo("service.direct.ru", 18081, socket.AF_INET, socket.SOCK_STREAM)
        assert rows and all(ipaddress.ip_address(row[4][0]) in ipaddress.ip_network("198.18.0.0/15") for row in rows)
        assert tcp(rows[0][4][0]) == "DIRECT"
        previous_fake = rows[0][4][0]
        for cycle in range(1, args.resolver_cycles):
            disconnect(); connect()
            # A cached libc/system-resolver result must retain its domain route
            # after a native helper restart, even without a new DNS query.
            assert tcp(previous_fake) == "DIRECT", "cached FakeIP identity changed after reconnect"
            name = f"reconnect-{cycle}.direct.ru"
            rows = socket.getaddrinfo(name, 18081, socket.AF_INET, socket.SOCK_STREAM)
            assert rows and all(ipaddress.ip_address(row[4][0]) in ipaddress.ip_network("198.18.0.0/15") for row in rows)
            previous_fake = rows[0][4][0]
            assert tcp(previous_fake) == "DIRECT"
        report["system_resolver_connect_cycles"] = args.resolver_cycles
        # Strict state can change live. It must coexist with DIRECT/VPN rules,
        # stay blocked after disconnect, and release only on explicit disable.
        toggle(True)
        probe({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1]]})
        disconnect()
        try:
            native_connect()
        except OSError:
            pass
        else:
            raise AssertionError("strict kill switch released traffic between sessions")
        connect()
        probe({"names": [["direct.ru", "DIRECT", 1], ["vpn.test", "VPN", 1]]})
        toggle(False)
        # App scope flows go through the actual singleton Qt service child.
        for mode, expected, other in ((2, "DIRECT", "VPN"), (1, "VPN", "DIRECT")):
            disconnect(); profile["appSplitTunnelType"] = mode
            profile["splitTunnelApps"] = [str(Path(sys.executable).resolve())]
            connect()
            probe({"names": [["vpn.test", expected, 1]], "other_process": str(args.peer.resolve()), "other_expected": other})
        disconnect(); profile.pop("appSplitTunnelType"); profile.pop("splitTunnelApps"); connect()
        # Loss of the GUI IPC connection must not destroy the service child.
        close_channel(); open_channel()
        send({"type": "status"}); assert wait("status")["connected"]
        assert tcp(resolve("vpn.test")) == "VPN"
        if win:
            parent = int(ps("(Get-CimInstance Win32_Service -Filter \"Name='AmneziaVPN-service'\").ProcessId"))
            pid = int(ps(f"(Get-CimInstance Win32_Process | Where-Object {{$_.Name -eq 'amnezia-routing.exe' -and $_.ParentProcessId -eq {parent}}}).ProcessId"))
            os.kill(pid, signal.SIGTERM)  # TerminateProcess, not a graceful stop
        else:
            parent = subprocess.check_output(["systemctl", "show", "AmneziaVPN", "--property=MainPID", "--value"], text=True).strip()
            pid = int(subprocess.check_output(["pgrep", "-P", parent, "-x", "amnezia-routing"], text=True).strip())
            os.kill(pid, signal.SIGKILL)
        seen = set()
        end = time.monotonic() + 20
        while not {"backendFailure", "disconnected"}.issubset(seen):
            row = events.get(timeout=max(0.1, end - time.monotonic()))
            seen.add(row.get("type"))
            assert time.monotonic() < end, "service failed to report child crash"
        try:
            native_connect()
        except OSError:
            pass
        else:
            raise AssertionError("installed helper crash released native traffic")
        disconnect()  # explicit service recovery, including the child's guard
        native_connect()
        connect(); assert tcp(resolve("vpn.test")) == "VPN"
        counts = observers()
        disconnect()
        native_connect()
        after = snapshot()
        assert after == before, "installed-service route/DNS restoration differed"
        report.update(installed_service="PASS", strict_kill_switch="PASS", system_resolver="PASS", application_scope="PASS", ipc_reconnect="PASS", helper_crash_recovery="PASS", observers=counts, os_state_restored=True)
    except Exception:
        # Retain the failed state before teardown; explicit DNS probes can pass
        # while libc/NSS uses a different resolver path. Never convert failure
        # into PASS or rewrite the runner's resolver as a diagnostic shortcut.
        report["resolver_diagnostics"] = resolver_diagnostics()
        print(json.dumps(report["resolver_diagnostics"], indent=2), flush=True)
        raise
    finally:
        if stream is not None:
            try:
                send({"type": "deactivate"})
                # Give the service's graceful cleanup/recovery time to finish.
                time.sleep(2)
            except (OSError, ValueError):
                pass
        try:
            toggle(False)
        finally:
            close_channel()
            if peer is not None: peer.terminate(); peer.wait(timeout=15)
            temporary.cleanup()
            args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
