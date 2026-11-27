#!/usr/bin/env python3
"""Run installed-service acceptance with a real cached systemd PID 1."""
import argparse
import json
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--evidence", type=Path, required=True)
parser.add_argument("--stage", type=Path, required=True)
parser.add_argument("--tag", required=True)
parser.add_argument("--os-libs", type=Path)
parser.add_argument("--dns-probe", type=Path)
parser.add_argument("--xray-probe", type=Path)
parser.add_argument("--openvpn-fixture", type=Path)
parser.add_argument("--installer", type=Path, help="Run the actual IFW installer into the disposable guest")
parser.add_argument("--maintenance-purge", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
evidence = args.evidence.resolve()
name = "amnezia-systemd-acceptance-2cpu-4g"
report = {}
openvpn_replica = None
openvpn_log = None
command = [
    "docker", "run", "-d", "--name", name, "--network", "none", "--cgroupns", "private",
    "--cap-add", "SYS_ADMIN", "--cap-add", "NET_ADMIN",
    "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
    "--device", "/dev/net/tun", "--cpus", "2", "--memory", "4g", "--memory-swap", "4g",
    "--tmpfs", "/run", "--tmpfs", "/tmp", "--stop-signal", "SIGRTMIN+3",
    "-e", "AMNEZIA_NATIVE_DNS_SERVICE_TEST=isolated-namespace", "-e", "container=docker",
    "-v", str(root) + ":/src:ro",
    "-v", str(evidence) + ":/evidence", "--entrypoint", "python3",
    "amnezia-two-hop-systemd-tests:latest", "/src/scripts/routing/boot_private_systemd.py",
]
if args.os_libs:
    command[2:2] = ["-v", str(args.os_libs.resolve()) + ":/usr/local/lib/amnezia-fixture-os:ro"]
if args.installer:
    command[2:2] = ["-e", "AMNEZIA_SYSTEMD_INSTALLER=1"]
else:
    command[2:2] = ["-v", str(args.stage.resolve()) + ":/opt/AmneziaVPN:ro"]
if args.dns_probe:
    command[2:2] = ["-v", "/usr:/host/usr:ro", "-e", "AMNEZIA_SYSTEMD_DNS_FIXTURE=1"]
subprocess.run(command, check=True, capture_output=True)


def execute(*arguments, timeout=20):
    result = subprocess.run(["docker", "exec", name, *arguments], capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        report.setdefault("failed_commands", []).append({
            "arguments": arguments, "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr})
        raise RuntimeError(str(arguments) + f" exit={result.returncode}: " + result.stdout + result.stderr)
    return result.stdout + result.stderr


try:
    deadline = time.monotonic() + 25
    while True:
        result = subprocess.run(["docker", "exec", name, "systemctl", "show",
                                 "-p", "SystemState", "--value"], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip() in ("running", "degraded"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError("systemd readiness: " + result.stdout + result.stderr)
        time.sleep(.2)
    report["pid1"] = execute("cat", "/proc/1/comm").strip()
    assert report["pid1"] == "systemd"
    report["manager_state"] = result.stdout.strip()
    if args.dns_probe:
        execute("systemctl", "start", "AmneziaFixtureResolved.service")
        deadline = time.monotonic() + 10
        while True:
            result = subprocess.run(["docker", "exec", name,
                "/host/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "--library-path",
                "/host/usr/lib/x86_64-linux-gnu:/host/usr/lib/x86_64-linux-gnu/systemd",
                "/host/usr/bin/busctl", "--address=unix:path=/run/amnezia-private-resolved/bus",
                "get-property", "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager", "DNS"], capture_output=True, text=True)
            if result.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("real resolved readiness: " + result.stderr)
            time.sleep(.1)
        execute("ip", "link", "add", "dns-systemd", "type", "dummy")
        execute("ip", "addr", "add", "192.0.2.10/32", "dev", "dns-systemd")
        execute("ip", "link", "set", "dns-systemd", "up")
    if args.installer:
        installer = "/evidence/" + str(args.installer.resolve().relative_to(evidence))
        report["installer_log"] = execute("env", "QT_QPA_PLATFORM=offscreen", installer,
            "--root", "/opt/AmneziaVPN", "--accept-licenses", "--default-answer",
            "--confirm-command", "--max-concurrent-operations", "2", "install", timeout=120)
        report["installed_native_closure"] = execute("python3", "-c",
            "from pathlib import Path; import hashlib,json,subprocess; "
            "p=Path('/opt/AmneziaVPN/bin'); m=json.loads((p/'openvpn-runtime.json').read_text()); "
            "assert hashlib.sha256((p/'openvpn').read_bytes()).hexdigest()==m['deployed_sha256']; "
            "assert all(hashlib.sha256((p/'openvpn-libs'/n).read_bytes()).hexdigest()==h for n,h in m['libraries'].items()); "
            "print(json.dumps(m)); print(subprocess.check_output(['ldd',str(p/'openvpn')],text=True))")
    report["unit"] = execute("systemctl", "cat", "AmneziaVPN.service")
    execute("systemctl", "start", "AmneziaVPN.service")
    report["initial"] = execute("systemctl", "show", "AmneziaVPN.service",
                                "-p", "MainPID", "-p", "ActiveState", "-p", "SubState")
    assert "ActiveState=active" in report["initial"] and "SubState=running" in report["initial"]
    execute("systemctl", "restart", "AmneziaVPN.service")
    report["restarted"] = execute("systemctl", "show", "AmneziaVPN.service",
                                  "-p", "MainPID", "-p", "ActiveState", "-p", "SubState")
    assert "ActiveState=active" in report["restarted"]
    if args.dns_probe:
        def probe(operation, record, library_path="/opt/AmneziaVPN/lib"):
            return execute("env", "LD_LIBRARY_PATH=" + library_path,
                "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/amnezia-private-resolved/bus",
                "/evidence/" + str(args.dns_probe.resolve().relative_to(evidence)),
                operation, "/evidence/" + record)
        def wait_ipc():
            deadline = time.monotonic() + 5
            while True:
                try:
                    probe("ready", "readiness-unused")
                    return
                except RuntimeError as error:
                    if ("exit=8:" not in str(error) and "exit=9:" not in str(error)) or time.monotonic() > deadline:
                        raise
                    time.sleep(.1)
        wait_ipc()
        # Ensure a restarted unit actually exposes working IPC, not just a live
        # process with a stale socket left by its predecessor.
        report["published"] = probe("publish", f"systemd-dns-crash-{args.tag}.json")
        old = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
        execute("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", "AmneziaVPN.service")
        deadline = time.monotonic() + 10
        while True:
            current = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
            if current not in ("0", old):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("systemd automatic restart deadline")
            time.sleep(.1)
        wait_ipc()
        report["crash_recovered"] = probe("inspect", f"systemd-dns-crash-{args.tag}.json")
        # A fresh process has empty in-memory DnsUtils, but still owns the
        # unresolved durable journal. It must not report a successful stop.
        startup_record = f"systemd-dns-startup-conflict-{args.tag}.json"
        report["startup_conflict_published"] = probe("publish", startup_record)
        probe("external", startup_record)
        old = current
        execute("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", "AmneziaVPN.service")
        deadline = time.monotonic() + 10
        while True:
            current = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
            if current not in ("0", old):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("conflicted startup automatic restart deadline")
            time.sleep(.1)
        wait_ipc()
        report["startup_conflict_preserved"] = probe("conflict", startup_record)
        execute("systemctl", "stop", "--no-block", "AmneziaVPN.service")
        time.sleep(.8)
        report["startup_conflict_pending_stop"] = execute("systemctl", "show", "AmneziaVPN.service",
                                                         "-p", "MainPID", "-p", "ActiveState")
        assert "ActiveState=deactivating" in report["startup_conflict_pending_stop"]
        assert "MainPID=" + current in report["startup_conflict_pending_stop"]
        probe("conflict", startup_record)
        probe("resolve", startup_record)
        deadline = time.monotonic() + 10
        while "ActiveState=inactive" not in execute("systemctl", "show", "AmneziaVPN.service", "-p", "ActiveState"):
            if time.monotonic() > deadline:
                raise RuntimeError("repaired startup recovery stop deadline")
            time.sleep(.1)
        report["startup_conflict_restored"] = probe("inspect", startup_record)
        execute("systemctl", "start", "AmneziaVPN.service")
        wait_ipc()
        report["republished"] = probe("publish", f"systemd-dns-stop-{args.tag}.json")
        probe("external", f"systemd-dns-stop-{args.tag}.json")
        pending_pid = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
        execute("systemctl", "stop", "--no-block", "AmneziaVPN.service")
        time.sleep(.8)
        report["pending_stop"] = execute("systemctl", "show", "AmneziaVPN.service",
                                         "-p", "MainPID", "-p", "ActiveState")
        assert "ActiveState=deactivating" in report["pending_stop"]
        assert "MainPID=" + pending_pid in report["pending_stop"] and pending_pid != "0"
        report["blocked_guard"] = probe("blocked", f"systemd-dns-stop-{args.tag}.json")
        probe("resolve", f"systemd-dns-stop-{args.tag}.json")
        deadline = time.monotonic() + 10
        while "ActiveState=inactive" not in execute("systemctl", "show", "AmneziaVPN.service", "-p", "ActiveState"):
            if time.monotonic() > deadline:
                raise RuntimeError("confirmed systemd stop deadline")
            time.sleep(.1)
    else:
        execute("systemctl", "stop", "AmneziaVPN.service")
    report["stopped"] = execute("systemctl", "show", "AmneziaVPN.service",
                                "-p", "ActiveState", "-p", "Result")
    assert "ActiveState=inactive" in report["stopped"] and "Result=success" in report["stopped"]
    if args.dns_probe:
        report["graceful_restored"] = probe("inspect", f"systemd-dns-stop-{args.tag}.json")
        report["remaining_journals"] = execute("python3", "-c",
            "from pathlib import Path; p=[p for r in ['/root/.config','/.config'] for p in Path(r).rglob('owned-*.json')]; print(p); assert not p")
    if args.xray_probe:
        execute("systemctl", "start", "AmneziaVPN.service")
        wait_ipc()
        state = f"systemd-xray-stop-{args.tag}.json"
        report["xray_published"] = execute("env", "LD_LIBRARY_PATH=/opt/AmneziaVPN/lib",
            "AMNEZIA_NATIVE_DNS_SERVICE_TEST=isolated-namespace",
            "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/amnezia-private-resolved/bus",
            "/evidence/" + str(args.xray_probe.resolve().relative_to(evidence)),
            "--publish-only", "/evidence/" + state)
        pid = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
        def children():
            return execute("python3", "-c",
                f"from pathlib import Path; p=Path('/proc/{pid}/task/{pid}/children'); "
                "print(' '.join(x for x in p.read_text().split() "
                "if Path('/proc/'+x+'/exe').resolve().name=='tun2socks'))").strip()
        worker = children()
        assert worker and len(worker.split()) == 1
        report["xray_worker_before"] = worker
        report["xray_capture_before"] = execute("ip", "-6", "route", "show", "table", "all")
        probe("external", state)
        execute("systemctl", "stop", "--no-block", "AmneziaVPN.service")
        time.sleep(.8)
        report["xray_pending_stop"] = execute("systemctl", "show", "AmneziaVPN.service",
                                              "-p", "MainPID", "-p", "ActiveState")
        assert "ActiveState=deactivating" in report["xray_pending_stop"]
        assert "MainPID=" + pid in report["xray_pending_stop"] and children() == worker
        assert execute("ip", "-6", "route", "show", "table", "all") == report["xray_capture_before"]
        report["xray_blocked_guard"] = probe("blocked", state)
        probe("resolve", state)
        deadline = time.monotonic() + 10
        while "ActiveState=inactive" not in execute("systemctl", "show", "AmneziaVPN.service", "-p", "ActiveState"):
            if time.monotonic() > deadline:
                raise RuntimeError("active Xray stop deadline")
            time.sleep(.1)
        report["xray_retired"] = probe("retired", state)
        report["xray_remaining_processes"] = execute("python3", "-c",
            f"from pathlib import Path; assert not Path('/proc/{worker}').exists(); print('worker exited')")
        report["xray_stopped"] = execute("systemctl", "show", "AmneziaVPN.service", "-p", "Result")
        assert "Result=success" in report["xray_stopped"]
    if args.openvpn_fixture:
        fixture = "/evidence/" + str(args.openvpn_fixture.resolve().relative_to(evidence))
        execute("python3", "-c",
            "from pathlib import Path; "
            f"Path('/etc/systemd/system/AmneziaFixtureOpenVpn.service').write_text("
            f"'[Service]\\nExecStart=/opt/AmneziaVPN/bin/openvpn --config {fixture}/server.conf\\n')")
        execute("systemctl", "daemon-reload")
        execute("systemctl", "start", "AmneziaFixtureOpenVpn.service")
        execute("systemctl", "start", "AmneziaVPN.service")
        wait_ipc()
        baseline = execute("ip", "-6", "route", "show", "table", "all") + execute("ip", "-6", "rule", "show")
        peer_log_path = evidence / f"systemd-openvpn-replica-{args.tag}.log"
        openvpn_log = peer_log_path.open("w")
        openvpn_replica = subprocess.Popen(["docker", "exec", name, "env",
            "LD_LIBRARY_PATH=/opt/AmneziaVPN/lib",
            fixture + "/peer-build/openvpn_qtro_peer", "start", fixture + "/client.conf",
            fixture + "/systemd-descriptor"], stdout=openvpn_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 15
        while ",CONNECTED,SUCCESS" not in peer_log_path.read_text():
            if openvpn_replica.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("systemd TLS OpenVPN readiness: " + peer_log_path.read_text())
            time.sleep(.1)
        state = f"systemd-openvpn-stop-{args.tag}.json"
        probe("snapshot-openvpn", state)
        execute("python3", "-c",
            "from pathlib import Path; import json,sys; p=Path(sys.argv[1]); "
            "r=json.loads(p.read_text()); r['baseline_capture']=sys.argv[2]; "
            "p.write_text(json.dumps(r,indent=2))", "/evidence/" + state, baseline)
        pid = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
        native = execute("python3", "-c",
            f"from pathlib import Path; p=Path('/proc/{pid}/task/{pid}/children'); "
            "print(' '.join(x for x in p.read_text().split() "
            "if Path('/proc/'+x+'/exe').resolve().name=='openvpn'))").strip()
        assert native and len(native.split()) == 1
        routes = execute("ip", "-6", "route", "show", "table", "all")
        report["openvpn_child_before"] = native
        probe("external", state)
        execute("systemctl", "restart", "--no-block", "AmneziaVPN.service")
        time.sleep(.8)
        report["openvpn_pending_restart"] = execute("systemctl", "show", "AmneziaVPN.service",
                                                   "-p", "MainPID", "-p", "ActiveState")
        assert "MainPID=" + pid in report["openvpn_pending_restart"]
        assert "ActiveState=deactivating" in report["openvpn_pending_restart"]
        execute("python3", "-c", f"from pathlib import Path; assert Path('/proc/{native}').exists()")
        assert routes == execute("ip", "-6", "route", "show", "table", "all")
        report["openvpn_blocked_guard"] = probe("blocked", state)
        probe("resolve", state)
        deadline = time.monotonic() + 15
        while True:
            current = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
            if current not in ("0", pid):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("active OpenVPN restart deadline")
            time.sleep(.1)
        if openvpn_replica.wait(timeout=10) != 0:
            raise RuntimeError("native OpenVPN did not finish normally: " + peer_log_path.read_text())
        report["openvpn_retired"] = probe("retired", state)
        report["openvpn_restarted_pid"] = current
        native_log = execute("python3", "-c",
            f"from pathlib import Path; print(Path({(fixture + '/native.log')!r}).read_text())")
        ack = native_log.find("MANAGEMENT: CMD 'needok 'AMNEZIA-DNS-RESTORE:")
        closed = native_log.lower().find("closing tun/tap interface")
        assert ack >= 0 and closed > ack
        assert "VERIFY EKU OK" in native_log and "VERIFY OK: depth=0, CN=server" in native_log
        execute("systemctl", "stop", "AmneziaVPN.service")
    report["validation"] = ("startup/restart/crash recovery/active DNS stop passed" if args.dns_probe
                            else "startup/restart/empty stop passed; active DNS ownership not yet exercised")
    if args.xray_probe:
        report["validation"] += "; active Xray child/protection stop passed"
    if args.openvpn_fixture:
        report["validation"] += "; active TLS OpenVPN child/protection restart passed"
    if args.maintenance_purge:
        if not args.installer:
            raise RuntimeError("--maintenance-purge requires an actual installer run")
        maintenance_command = ["docker", "exec", name, "env", "QT_QPA_PLATFORM=offscreen",
            "/opt/AmneziaVPN/maintenancetool", "--root", "/opt/AmneziaVPN",
            "--accept-licenses", "--default-answer", "--confirm-command", "purge"]
        if args.dns_probe:
            execute("systemctl", "start", "AmneziaVPN.service")
            wait_ipc()
            # The final observer must outlive removal of the tested payload.
            # Copy only its measured installed ELF dependencies into fixture
            # storage, never into or over the production installation.
            report["maintenance_observer_dependencies"] = execute("env",
                "LD_LIBRARY_PATH=/opt/AmneziaVPN/lib", "python3", "-c",
                "import subprocess,re,shutil,json; from pathlib import Path; "
                "out=Path('/var/tmp/amnezia-maintenance-probe-libs'); out.mkdir(); copied={}; "
                "lines=subprocess.check_output(['ldd',"
                + repr("/evidence/" + str(args.dns_probe.resolve().relative_to(evidence))) + "],text=True); "
                "matches=re.findall(r'(\\S+) => (/opt/AmneziaVPN/\\S+) ',lines); "
                "[(shutil.copy2(p,out/n),copied.update({n:p})) for n,p in matches]; "
                "print(json.dumps(copied))")
            state = f"systemd-maintenance-stop-{args.tag}.json"
            report["maintenance_published"] = probe("publish", state)
            probe("external", state)
            pid = execute("systemctl", "show", "AmneziaVPN.service", "-p", "MainPID", "--value").strip()
            # Exercise entry while deactivation is already in progress, not only
            # the active-state branch of the installer hook.
            execute("systemctl", "stop", "--no-block", "AmneziaVPN.service")
            maintenance_path = evidence / f"systemd-maintenance-{args.tag}.log"
            with maintenance_path.open("w") as maintenance_log:
                maintenance = subprocess.Popen(maintenance_command, stdout=maintenance_log,
                                               stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        assert maintenance.poll() is None, maintenance_path.read_text()
                        pending = execute("systemctl", "show", "AmneziaVPN.service",
                                          "-p", "MainPID", "-p", "ActiveState")
                        if "Uninstall Script started" in execute("cat", "/var/log/AmneziaVPN/post-uninstall.log"):
                            break
                        if time.monotonic() > deadline:
                            raise RuntimeError("maintenance undo hook readiness deadline")
                        time.sleep(.1)
                    time.sleep(.8)
                    assert maintenance.poll() is None, maintenance_path.read_text()
                    assert "ActiveState=deactivating" in pending and "MainPID=" + pid in pending
                    report["maintenance_pending_stop"] = pending
                    report["maintenance_blocked_guard"] = probe("blocked", state)
                    execute("python3", "-c",
                        "from pathlib import Path; "
                        "assert Path('/etc/systemd/system/AmneziaVPN.service').is_file(); "
                        "assert Path('/opt/AmneziaVPN/bin/openvpn').is_file(); "
                        "assert Path('/opt/AmneziaVPN/bin/AmneziaVPN-service').is_file()")
                    probe("resolve", state)
                    assert maintenance.wait(timeout=120) == 0, maintenance_path.read_text()
                finally:
                    if maintenance.poll() is None:
                        maintenance.terminate()
                        maintenance.wait(timeout=5)
            report["maintenance_log"] = maintenance_path.read_text()
            report["maintenance_restored"] = probe("inspect", state, "/var/tmp/amnezia-maintenance-probe-libs")
        else:
            report["maintenance_log"] = execute(*maintenance_command[3:], timeout=120)
        report["removed_unit"] = execute("systemctl", "show", "AmneziaVPN.service", "-p", "LoadState")
        assert "LoadState=not-found" in report["removed_unit"]
        execute("python3", "-c",
            "from pathlib import Path; assert not Path('/opt/AmneziaVPN/bin/openvpn').exists(); "
            "assert not Path('/opt/AmneziaVPN/bin/AmneziaVPN-service').exists()")
        report["validation"] += "; actual IFW maintenance purge passed"
    print(json.dumps(report, indent=2), flush=True)
finally:
    try:
        report["final_addresses"] = execute("ip", "-j", "address")
        report["durable_journals"] = execute("python3", "-c",
            "from pathlib import Path; import json; "
            "print(json.dumps({str(p):p.read_text() for r in ['/root/.config','/.config'] for p in Path(r).rglob('owned-*.json')}))")
        if args.openvpn_fixture and openvpn_replica:
            path = "/evidence/" + str(args.openvpn_fixture.resolve().relative_to(evidence)) + "/native.log"
            report["openvpn_native_log"] = execute("python3", "-c",
                f"from pathlib import Path; p=Path({path!r}); print(p.read_text() if p.exists() else 'no native log')")
        report["service_config_environment"] = execute("python3", "-c",
            "from pathlib import Path; import subprocess; "
            "pid=subprocess.check_output(['systemctl','show','AmneziaVPN.service','-p','MainPID','--value'],text=True).strip(); "
            "p=Path('/proc/'+pid+'/environ'); print([x for x in p.read_bytes().split(bytes([0])) "
            "if x.startswith((b'HOME=',b'XDG_CONFIG_HOME='))] if p.exists() else 'no running main')")
    except RuntimeError as error:
        report["final_state_error"] = str(error)
    if openvpn_replica and openvpn_replica.poll() is None:
        openvpn_replica.terminate()
        openvpn_replica.wait(timeout=5)
    if openvpn_log:
        openvpn_log.close()
    try:
        report["journal"] = execute("journalctl", "-u", "AmneziaVPN.service", "--no-pager", "-n", "100")
    except RuntimeError as error:
        report["journal_error"] = str(error)
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    (evidence / f"systemd-manager-boot-{args.tag}.log").write_text(logs.stdout + logs.stderr)
    (evidence / f"systemd-installed-startup-{args.tag}.json").write_text(json.dumps(report, indent=2))
    subprocess.run(["docker", "stop", "-t", "10", name], capture_output=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
