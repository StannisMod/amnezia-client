#!/usr/bin/env python3
"""Compile a standalone instrumentation APK and test a real feature APK.

Only use a disposable rooted AOSP/google_apis emulator. No external VPN server,
accounts, production profile, Qt rebuild or changes to the shipping APK source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import zipfile
import urllib.request
import threading


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "org.amnezia.vpn"


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def adb(*args):
    return run("adb", *args, capture_output=True, text=True).stdout.strip()


def payload_hashes(path):
    with zipfile.ZipFile(path) as apk:
        return {name: hashlib.sha256(apk.read(name)).hexdigest()
                for name in apk.namelist() if name.startswith("lib/") and name.endswith(".so")}


def check_ipc_contract():
    """Fail instead of silently using wrong ordinal messages after refactors."""
    source = (ROOT / "client/android/src/org/amnezia/vpn/IpcMessage.kt").read_text()
    for name, entries in {
        "Action": ["REGISTER_CLIENT", "UNREGISTER_CLIENT", "CONNECT", "DISCONNECT", "REQUEST_STATUS", "NOTIFICATION_PERMISSION_GRANTED", "SET_SAVE_LOGS", "UPDATE_APPLICATION_POLICY"],
        "ServiceEvent": ["STATUS_CHANGED", "STATUS", "STATISTICS_UPDATE", "ERROR", "APPLICATION_POLICY_RESULT"],
    }.items():
        match = re.search(r"enum class " + name + r"\s*:\s*IpcMessage\s*\{([^}]+)\}", source)
        assert match and re.findall(r"\b[A-Z_]+\b", match[1]) == entries, name + " IPC contract changed"
    source = (ROOT / "client/android/protocolApi/src/main/kotlin/ProtocolState.kt").read_text()
    assert re.findall(r"\b[A-Z_]+\b", source.split("enum class ProtocolState", 1)[1]) == [
        "DISCONNECTED", "CONNECTED", "CONNECTING", "DISCONNECTING", "RECONNECTING", "UNKNOWN"]


def snapshot():
    pid = adb("shell", "pidof", "org.amnezia.vpn:amneziaAwgService").split()
    assert len(pid) == 1 and pid[0].isdigit(), "real service process is missing or duplicated"
    status = adb("shell", "cat", f"/proc/{pid[0]}/status")
    descriptors = adb("shell", "ls", f"/proc/{pid[0]}/fd").split()
    targets = adb("shell", f'for fd in /proc/{pid[0]}/fd/*; do readlink "$fd" || true; done').splitlines()
    link_text = adb("shell", "ip", "link", "show")
    capture_links = {name: int(index) for index, name in re.findall(r"(?m)^([0-9]+): ([^: ]+):", link_text) if name.startswith("tun")}
    fields = adb('shell','cat',f'/proc/{pid[0]}/stat').split(')',1)[1].split()
    return {"cpu_ticks":int(fields[11])+int(fields[12]),"captured_at":time.monotonic(),"capture_links": capture_links, "pid": int(pid[0]), "fd_count": len(descriptors),
            "eventfds": targets.count("anon_inode:[eventfd]"),
            "capture_fds": sum(target in ("/dev/tun", "/dev/net/tun", "anon_inode:[tun]") for target in targets),
            "uid": int(re.search(r"^Uid:\s+(\d+)", status, re.M)[1]),
            "threads": int(re.search(r"^Threads:\s+(\d+)", status, re.M)[1]),
            "rss_kib": int(re.search(r"^VmRSS:\s+(\d+)", status, re.M)[1])}



def fault_host_guard():
    if Path('/.dockerenv').exists():
        links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True))
        assert {row['ifname'] for row in links} <= {'lo', 'stability6'}, 'fault tests require Docker --network none'
    else:
        assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'fault tests require an isolated Docker or disposable GitHub-hosted runner'


def nft_command(*args, text=None, check=True):
    prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
    return subprocess.run(prefix + ['nft', *args], input=text, text=True, capture_output=True, check=check, timeout=10)


def performance_metrics(output, report):
    measurements=[json.loads(row) for row in re.findall(r'PERFORMANCE (\{[^\n]*\})',output)]
    assert {r['backend'] for r in measurements}=={'legacy','shared'}, 'performance comparison missing'
    for row in measurements:
        before=report['retained_resources']['perf_'+row['backend']+'_before']
        after=report['retained_resources']['perf_'+row['backend']+'_after']
        assert before['pid']==after['pid'], 'performance process replaced'
        row.update(cpu_ticks=after['cpu_ticks']-before['cpu_ticks'],rss_before_kib=before['rss_kib'],rss_after_kib=after['rss_kib'])
    report['performance_emulator']=measurements


def upload_mtu_metrics(output, report):
    upload = re.search(r'MTU_UPLOAD_RESULT (\{[^\n]*\})', output)
    assert upload, 'automatic upload MTU result missing'
    metrics = report['automatic_upload_mtu'] = json.loads(upload[1])
    assert metrics['same_session'] and metrics['filter_still_active']
    assert metrics['original_tcp_accepts'] == 2
    assert metrics['age_before_fault_ms'] >= 65000, 'MTU fault must affect established sockets after normal probe periods'
    assert report['dropped_outer_packets']['restore_upload_mtu'] > 0
    a, b = (report['retained_resources'][key] for key in ('upload_mtu_before', 'upload_mtu_after'))
    assert a['pid'] == b['pid'] and a['capture_links'] and a['capture_links'] == b['capture_links']
    assert a['capture_fds'] == b['capture_fds'] == 1


def app_policy_metrics(output, report):
    match = re.search(r'APP_POLICY_RESULT (\{[^\n]*\})', output)
    assert match, 'two-application policy result missing'
    metrics = report['per_application_policy'] = json.loads(match[1])
    assert len(metrics['uids']) == 2 and len(set(metrics['uids'])) == 2 and min(metrics['uids']) > 0
    assert metrics['same_session'] and metrics['same_old_ports'] and metrics['dns_contexts_switched']
    a,b = (report['retained_resources'][key] for key in ('app_policy_before','app_policy_after'))
    assert a['pid'] == b['pid'] and a['capture_links'] and a['capture_links'] == b['capture_links']
    assert a['capture_fds'] == b['capture_fds'] == 1


def build_application_probes(tools, android_jar, work, sign):
    probe_apks = []
    probe_source = ROOT / 'scripts/routing/android-app-probe'
    probe_classes, probe_dex = work/'app-probe-classes', work/'app-probe-dex'
    probe_classes.mkdir(); probe_dex.mkdir()
    run('javac','-source','8','-target','8','-classpath',android_jar,'-d',probe_classes,probe_source/'Probe.java')
    run(tools/'d8','--min-api','28','--lib',android_jar,'--output',probe_dex,*sorted(probe_classes.rglob('*.class')))
    for suffix in ('a','b'):
        package = 'org.amnezia.routingprobe.'+suffix
        manifest = work/('probe-'+suffix+'-manifest.xml')
        manifest.write_text((probe_source/'AndroidManifest.xml.in').read_text().replace('@PACKAGE@',package))
        unsigned_probe = work/('probe-'+suffix+'-unsigned.apk')
        run(tools/'aapt2','link','-I',android_jar,'--manifest',manifest,'-o',unsigned_probe)
        with zipfile.ZipFile(unsigned_probe,'a') as archive: archive.write(probe_dex/'classes.dex','classes.dex')
        signed_probe = work/('probe-'+suffix+'.apk')
        sign(unsigned_probe,signed_probe); probe_apks.append(signed_probe)
    return probe_apks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True, help="private JSON generated by the running host peer")
    parser.add_argument("--quic-probe", type=Path, required=True)
    parser.add_argument("--quic-ca", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--source-sha", help="test-harness commit when a read-only worktree has no mounted Git metadata")
    parser.add_argument("--apk-source-sha", help="record the actual packaged client source independently of the harness")
    parser.add_argument("--diagnose-control", action="store_true", help="capture slow control-path stacks before timeout; diagnostic result only")
    parser.add_argument("--package-lifecycle", action="store_true", help="with --app-policy-only, reinstall a captured app and require fresh-UID VPN capture")
    parser.add_argument("--app-policy-only", action="store_true", help="focused two-app live policy regression; not full acceptance")
    parser.add_argument("--upload-mtu-only", action="store_true", help="focused aged-TCP MTU regression; not full acceptance")
    parser.add_argument("--primary-only", action="store_true", help="focused retained-TCP debug run; not full acceptance")
    parser.add_argument("--performance-only",action="store_true",help="benchmark only; does not run full acceptance")
    parser.add_argument("--performance-order",choices=("legacy-first","shared-first"),default="legacy-first")
    args = parser.parse_args()
    assert not args.package_lifecycle or args.app_policy_only, '--package-lifecycle requires --app-policy-only'
    if sum((args.app_policy_only, args.upload_mtu_only, args.primary_only, args.performance_only)) > 1:
        parser.error("focused acceptance modes are mutually exclusive")
    check_ipc_contract()
    for value in (args.source_sha, args.apk_source_sha):
        assert value is None or re.fullmatch(r'[0-9a-f]{40}', value), 'invalid source revision'
    source_sha = args.source_sha or run('git', 'rev-parse', 'HEAD', cwd=ROOT, capture_output=True, text=True).stdout.strip()
    fault_host_guard()
    fixture = json.loads(args.fixture.read_text())
    protocol = fixture['protocol']
    peer_port = int(fixture[protocol + '_config_data']['port'])
    assert 1 <= peer_port <= 65535
    fault_table = 'aap_' + str(os.getpid())
    timer = None
    control_timers = {}
    diagnostic_taken = threading.Event()
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    sdk = Path(os.environ["ANDROID_HOME"])
    tools = sdk / "build-tools/36.0.0"
    android_jar = sdk / "platforms/android-36/android.jar"
    assert android_jar.is_file(), "install platforms;android-36 first"
    # Neither key nor fixture is uploaded as an artifact. Re-sign only the
    # disposable copy and verify every native payload byte remains identical.
    key = work / "emulator-test.jks"
    run("keytool", "-genkeypair", "-keystore", key, "-alias", "test", "-storepass", "android",
        "-keypass", "android", "-dname", "CN=Disposable emulator", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def sign(source, target):
        aligned_source = target.with_name(target.stem + "-aligned-input.apk")
        run(tools / "zipalign", "-f", "4", source, aligned_source)
        run(tools / "apksigner", "sign", "--ks", key, "--ks-key-alias", "test", "--ks-pass", "pass:android",
            "--key-pass", "pass:android", "--out", target, aligned_source)
        run(tools / "apksigner", "verify", target)
        aligned_source.unlink()
    target = work / "feature-test.apk"
    sign(args.apk.resolve(), target)
    assert payload_hashes(target) == payload_hashes(args.apk), "re-sign changed native payload"

    classes = work / "classes"; classes.mkdir(exist_ok=True)
    dex = work / "dex"; dex.mkdir(exist_ok=True)
    source = ROOT / "scripts/routing/android"
    run("javac", "-source", "8", "-target", "8", "-classpath", android_jar, "-d", classes, *sorted(source.glob("*.java")))
    run(tools / "d8", "--min-api", "28", "--lib", android_jar, "--output", dex, *sorted(classes.rglob("*.class")))
    unsigned = work / "instrumentation-unsigned.apk"
    resources = work / "policy-resources.zip"
    run(tools / "aapt2", "compile", "--dir", source / "res", "-o", resources)
    run(tools / "aapt2", "link", "-I", android_jar, "--manifest", source / "AndroidManifest.xml", "-R", resources, "-o", unsigned)
    with zipfile.ZipFile(unsigned, "a") as apk:
        apk.write(dex / "classes.dex", "classes.dex")
        apk.write(args.fixture, "assets/fixture.json")
        apk.write(args.quic_ca, "assets/quic-ca.der")
        apk.write(args.quic_probe, "lib/x86_64/libtrafficprobe.so")
    aligned = work / "instrumentation-aligned.apk"
    run(tools / "zipalign", "-f", "4", unsigned, aligned)
    instrument = work / "instrumentation.apk"
    sign(aligned, instrument)

    probe_apks, probe_processes, probe_logs = [], [], []
    if not (args.upload_mtu_only or args.primary_only or args.performance_only):
        probe_apks = build_application_probes(tools, android_jar, work, sign)

    assert adb("shell", "getprop", "ro.kernel.qemu") == "1", "only disposable Android emulators are supported"
    adb("root"); adb("wait-for-device")
    assert adb("shell", "id", "-u") == "0", "rooted emulator is needed to measure the actual service process"
    report = {"schema_version": 1, "source_sha": source_sha, "apk_source_sha": args.apk_source_sha,
              "apk_sha256": hashlib.sha256(args.apk.read_bytes()).hexdigest(), "native_payloads": payload_hashes(args.apk),
              "environment": "disposable Android emulator; independent host and AWG-netstack observers",
              "protocol": protocol, "cycles_requested": args.cycles,
              "retained_resources": {}, "native_vpn_acceptance": "FAIL", "resources": {},
              "not_run": ["physical device", "Wi-Fi/cellular handover", "Android 9 lockdown query restriction", "physical-device policy behavior", "performance parity"]}
    admin = "org.amnezia.routingtest/.RoutingPolicyReceiver"
    try:
        # Only the emulator was accepted above. Remove stale test-only device
        # ownership/signatures from an interrupted prior disposable run.
        subprocess.run(['adb', 'shell', 'dpm', 'remove-active-admin', admin], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        for package in ('org.amnezia.routingtest', PACKAGE, 'org.amnezia.routingprobe.a', 'org.amnezia.routingprobe.b'):
            subprocess.run(['adb', 'uninstall', package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        adb("shell", "settings", "put", "global", "private_dns_mode", "off")
        adb("install", "-r", "-t", str(target))
        adb("install", "-r", "-t", str(instrument))
        for index,probe_apk in enumerate(probe_apks):
            adb('install','-r','-t',str(probe_apk))
            suffix = ('a','b')[index]
            log = (work/('app-probe-'+suffix+'.log')).open('w'); probe_logs.append(log)
            probe_processes.append(subprocess.Popen(['adb','shell','am','instrument','-w','-r','-e','port',str(19091+index),
                'org.amnezia.routingprobe.'+suffix+'/org.amnezia.appprobe.Probe'],stdout=log,stderr=subprocess.STDOUT))
        assert "Success" in adb("shell", "dpm", "set-device-owner", admin), "AVD device owner setup failed"
        adb("shell", "appops", "set", PACKAGE, "ACTIVATE_VPN", "allow")
        # am instrument does not set a useful shell exit code on test failure.
        # Require the explicit PASS result and successful resource assertions.
        command = ["adb", "shell", "am", "instrument", "-w", "-r", "-e", "cycles", str(args.cycles),
                   "-e", "primary_only", str(args.primary_only).lower(),
                   "-e", "upload_mtu_only", str(args.upload_mtu_only).lower(),
                   "-e", "app_policy_only", str(args.app_policy_only).lower(),
                   "-e", "package_lifecycle", str(args.package_lifecycle).lower(),
                   "-e", "diagnose_control", str(args.diagnose_control).lower(),
                   "-e", "performance_only", str(args.performance_only).lower(),
                   "-e", "performance_order", args.performance_order,
                   "org.amnezia.routingtest/org.amnezia.routingtest.RoutingInstrumentation"]
        with (work / "instrumentation.log").open("w") as log:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            timer = threading.Timer(2400, process.kill); timer.daemon = True; timer.start()
            started = time.monotonic(); output = []
            for line in process.stdout:
                print(line, end="", flush=True); log.write(line); log.flush(); output.append(line)
                if 'PACKAGE_LIFECYCLE_REINSTALL_B' in line:
                    assert args.package_lifecycle and args.app_policy_only, 'unexpected package mutation request'
                    (work/'package-before-connectivity.log').write_text(adb('shell','dumpsys','connectivity'))
                    package='org.amnezia.routingprobe.b'
                    assert 'Success' in adb('uninstall',package)
                    probe_processes[1].wait(timeout=15)
                    assert 'Success' in adb('install','-t',str(probe_apks[1]))
                    lifecycle_log=(work/'app-probe-b-reinstalled.log').open('w');probe_logs.append(lifecycle_log)
                    probe_processes.append(subprocess.Popen(['adb','shell','am','instrument','-w','-r','-e','port','19092',package+'/org.amnezia.appprobe.Probe'],stdout=lifecycle_log,stderr=subprocess.STDOUT))
                    (work/'package-after-connectivity.log').write_text(adb('shell','dumpsys','connectivity'))
                    adb('shell','touch',f'/data/user/0/{PACKAGE}/files/routing-package-reinstalled.ready')
                if 'PACKAGE_LIFECYCLE_UIDS ' in line:
                    report['package_lifecycle_uids']=json.loads(line.strip().split('PACKAGE_LIFECYCLE_UIDS ',1)[1])
                if 'PACKAGE_LIFECYCLE_RESULT ' in line:
                    report['package_lifecycle']=json.loads(line.strip().split('PACKAGE_LIFECYCLE_RESULT ',1)[1])
                if args.diagnose_control and 'CONTROL_PENDING ' in line:
                    request_id = int(line.strip().split('CONTROL_PENDING ',1)[1])
                    def capture_slow_control(request_id=request_id):
                        if diagnostic_taken.is_set(): return
                        diagnostic_taken.set()
                        try:
                            pid = snapshot()['pid']
                            trace = subprocess.run(['adb','shell','debuggerd','-b',str(pid)],capture_output=True,text=True,timeout=6)
                            (work/f'slow-control-{request_id}.log').write_text(trace.stdout+trace.stderr)
                            sockets = subprocess.run(['adb','shell','ss','-nto'],capture_output=True,text=True,timeout=3)
                            (work/f'slow-control-{request_id}-sockets.log').write_text(sockets.stdout+sockets.stderr)
                        except (AssertionError,subprocess.SubprocessError) as error:
                            (work/f'slow-control-{request_id}.log').write_text(type(error).__name__)
                    watch = threading.Timer(2, capture_slow_control);watch.daemon=True
                    control_timers[request_id]=watch;watch.start()
                if args.diagnose_control and 'CONTROL_FINISHED ' in line:
                    request_id = int(line.strip().split('CONTROL_FINISHED ',1)[1])
                    if request_id in control_timers: control_timers[request_id].cancel()
                if "RETAIN_CHECKPOINT " in line:
                    name = line.strip().split("RETAIN_CHECKPOINT ", 1)[1]
                    assert name in ('before', 'after', 'restore_mtu', 'drop_mtu', 'drop_before_media', 'restore_before_media', 'drop_with_media', 'restore_with_media', 'wifi_off', 'wifi_on', 'safe_policy_before', 'safe_policy_after', 'perf_legacy_before', 'perf_legacy_after', 'perf_shared_before', 'perf_shared_after', 'upload_mtu_before', 'drop_upload_mtu', 'upload_mtu_after', 'restore_upload_mtu', 'app_policy_before', 'app_policy_after', 'package_refreshed')
                    if name == 'package_refreshed':
                        assert args.package_lifecycle, 'unexpected package refresh checkpoint'
                        (work/'package-refreshed-connectivity.log').write_text(adb('shell','dumpsys','connectivity'))
                        (work/'package-refreshed-rules.log').write_text(adb('shell','ip','rule','show'))
                        (work/'package-refreshed-routes.log').write_text(adb('shell','ip','route','show','table','all'))
                    if name == 'before' and os.environ.get('AWG_ECHO_LAB') == '1':
                        observations=[]
                        for size in (128,576,1104,1280):
                            with urllib.request.urlopen('http://127.0.0.1:18080/lab-echo?size='+str(size),timeout=3) as response:
                                observations.append(json.load(response))
                        report['android_echo_lab']=observations
                        print('ANDROID_ECHO_LAB '+json.dumps(observations),flush=True)
                    if name.startswith('drop_'):
                        nft_command('delete', 'table', 'inet', fault_table, check=False)
                        rules = (f'add table inet {fault_table}\n'
                                 f'add chain inet {fault_table} output {{ type filter hook output priority -10; policy accept; }}\n'
                                 f'add chain inet {fault_table} input {{ type filter hook input priority -10; policy accept; }}\n'
                                 f'add rule inet {fault_table} output ip daddr 127.0.0.1 udp dport {peer_port} counter drop\n'
                                 f'add rule inet {fault_table} input ip saddr 127.0.0.1 udp sport {peer_port} counter drop\n')
                        if name == 'drop_mtu':
                            rules = (f'add table inet {fault_table}\n'
                                     f'add chain inet {fault_table} output {{ type filter hook output priority -10; policy accept; }}\n'
                                     f'add rule inet {fault_table} output ip saddr 127.0.0.1 udp sport {peer_port} ip length > 1200 counter drop\n')
                        if name == 'drop_upload_mtu':
                            rules = (f'add table inet {fault_table}\n'
                                     f'add chain inet {fault_table} input {{ type filter hook input priority -10; policy accept; }}\n'
                                     f'add rule inet {fault_table} input ip saddr 127.0.0.1 udp dport {peer_port} ip length > 1200 counter drop\n')
                        nft_command('-f', '-', text=rules)
                    elif name.startswith('restore_'):
                        witness = json.loads(nft_command('-j', 'list', 'table', 'inet', fault_table).stdout)
                        dropped = sum(expr['counter']['packets'] for entry in witness['nftables'] if 'rule' in entry
                                      for expr in entry['rule']['expr'] if 'counter' in expr)
                        assert dropped > 0, 'outer blackhole affected no encrypted packets'
                        report.setdefault('dropped_outer_packets', {})[name] = dropped
                        nft_command('delete', 'table', 'inet', fault_table)
                        if name == 'restore_mtu':
                            report['mtu_restored_wall_ns'] = time.time_ns()
                            print(f"RESTORED_NS={report['mtu_restored_wall_ns']}", flush=True)
                    elif name == 'wifi_off': adb('shell', 'svc', 'wifi', 'disable')
                    elif name == 'wifi_on': adb('shell', 'svc', 'wifi', 'enable')
                    if name in ('before', 'after', 'safe_policy_before', 'safe_policy_after', 'perf_legacy_before', 'perf_legacy_after', 'perf_shared_before', 'perf_shared_after', 'upload_mtu_before', 'upload_mtu_after', 'app_policy_before', 'app_policy_after'):
                        report['retained_resources'][name] = snapshot()
                    with urllib.request.urlopen('http://127.0.0.1:18080/stats', timeout=5) as response:
                        stats = json.load(response)
                    local = work / ('stats-' + name + '.json');local.write_text(json.dumps(stats))
                    remote = f'/data/user/0/{PACKAGE}/files/routing-stats-{name}.json'
                    adb('push', str(local), remote);adb('shell', 'restorecon', remote);adb('shell', 'chmod', '644', remote)
                    adb('shell', 'touch', f'/data/user/0/{PACKAGE}/files/routing-retain-{name}.ready')
                if "POLICY_CHECKPOINT " in line:
                    mode = line.strip().split("POLICY_CHECKPOINT ", 1)[1]
                    assert mode in ("off", "alwayson", "lockdown")
                    output_policy = adb("shell", "am", "broadcast", "-a", "org.amnezia.routingtest.POLICY", "-n", admin, "--es", "mode", mode)
                    assert "result=-1" in output_policy, "AVD VPN policy was not applied: " + output_policy
                    if mode == "off":
                        # Removing an always-on package revokes its VPN grant.
                        # Emulate renewed user consent before the recovery test.
                        adb("shell", "appops", "set", PACKAGE, "ACTIVATE_VPN", "allow")
                    adb("shell", "touch", f"/data/user/0/{PACKAGE}/files/routing-policy-{mode}.ready")
                if "RESOURCE_CHECKPOINT " in line:
                    label = line.strip().split("RESOURCE_CHECKPOINT ", 1)[1]
                    try:
                        report["resources"][label] = snapshot()
                    except (AssertionError, subprocess.CalledProcessError) as error:
                        if label != "failure":
                            raise
                        # Preserve the instrumentation's original failure even
                        # when that failure terminated the service process.
                        report["resources"][label] = {"snapshot_error": type(error).__name__}
                    if label == "failure":
                        failed = report['resources'].get('failure', {})
                        if 'pid' in failed:
                            try:
                                trace = subprocess.run(['adb','shell','debuggerd','-b',str(failed['pid'])],capture_output=True,text=True,timeout=8)
                                (work/'failure-native-backtrace.log').write_text(trace.stdout+trace.stderr)
                            except subprocess.TimeoutExpired:
                                (work/'failure-native-backtrace.log').write_text('Native backtrace timed out\n')
                        for name, command in {
                            "routes": ("shell", "ip", "route", "show", "table", "all"),
                            "rules": ("shell", "ip", "rule"),
                            "connectivity": ("shell", "dumpsys", "connectivity"),
                        }.items():
                            (work / ("failure-" + name + ".log")).write_text(adb(*command))
                if time.monotonic() - started > 2400:
                    process.kill(); raise TimeoutError("Android acceptance exceeded 40 minutes")
            assert process.wait(timeout=15) == 0
            timer.cancel()
        output = "".join(output)
        if args.app_policy_only:
            assert 'INSTRUMENTATION_RESULT: routing_result=PASS_APP_POLICY_ONLY' in output
            app_policy_metrics(output,report)
            if args.package_lifecycle:
                assert report.get('package_lifecycle') == {'uid_changed':True,'unaffected_tcp_preserved':True,'vpn_tcp_dns':True,'same_session':True}
            report['native_vpn_acceptance']='NOT_RUN_PACKAGE_LIFECYCLE_ONLY' if args.package_lifecycle else 'NOT_RUN_APP_POLICY_ONLY'
            return
        if args.upload_mtu_only:
            assert 'INSTRUMENTATION_RESULT: routing_result=PASS_UPLOAD_MTU_ONLY' in output
            upload_mtu_metrics(output, report)
            report['native_vpn_acceptance'] = 'NOT_RUN_UPLOAD_MTU_ONLY'
            return
        if args.performance_only:
            assert 'INSTRUMENTATION_RESULT: routing_result=PASS_PERFORMANCE_ONLY' in output
            performance_metrics(output,report)
            report['native_vpn_acceptance']='NOT_RUN_PERFORMANCE_ONLY'
            return
        if args.primary_only:
            assert "INSTRUMENTATION_RESULT: routing_result=PASS_PRIMARY_ONLY" in output, 'focused TCP acceptance failed'
            report['native_vpn_acceptance'] = 'PASS_PRIMARY_ONLY'
        else:
            assert "INSTRUMENTATION_RESULT: routing_result=PASS\n" in output, "Android service acceptance failed; see instrumentation.log"
            before, after = (report["resources"][label] for label in ("baseline", "after_cycles"))
            assert before["pid"] == after["pid"], "service process replacement hid resource cleanup"
            assert after["fd_count"] <= before["fd_count"] + 8, "descriptor growth across reconnects"
            assert after["threads"] <= before["threads"] + 24, "thread growth across reconnects"
            report["resource_limits"] = {"fd_growth": 8, "thread_growth": 24, "rss": "measured only; Go heap retention varies"}
            report["native_vpn_acceptance"] = "PASS_WITH_CONTROL_DIAGNOSTICS" if args.diagnose_control else "PASS"
            report["android_os_always_on_lockdown"] = "PASS"
            report["legacy_awg_transition"] = "PASS"
        match = re.search(r'INSTRUMENTATION_RESULT: retained_result=(\{[^\n]*\})', output)
        assert match, 'retained TCP result missing'
        report['retained_tcp'] = json.loads(match[1])
        metrics = {}
        for record in re.findall(r'MTU_RESULT ([^\r\n]+)', output):
            for field, value in re.findall(r'(\w+)=(\d+)', record):
                metrics[field] = int(value)
        assert metrics.keys() >= {'short_echoes', 'media_chunks', 'verified_large_downlink_ms', 'media_resumed_after_restore_ms'}, 'incomplete size-loss measurements'
        report['size_loss_measurements'] = metrics
        for first, last in ([('before', 'after')] if args.primary_only else [('before', 'after'), ('safe_policy_before', 'safe_policy_after')]):
            a, b = report['retained_resources'][first], report['retained_resources'][last]
            assert a['pid'] == b['pid'] and a['capture_links'] and a['capture_links'] == b['capture_links'], 'network/policy change recreated service or TUN'
            assert a['capture_fds'] == 1 and b['capture_fds'] == 1, 'capture ownership changed'
        if not args.primary_only:
            upload_mtu_metrics(output, report)
            app_policy_metrics(output, report)
            performance_metrics(output,report)
        report['ordinary_app_only_preserving_recovery'] = 'PASS'
        if not args.primary_only: report['all_vpn_lockdown'] = 'PASS'
    finally:
        if timer is not None: timer.cancel()
        for watch in control_timers.values(): watch.cancel()
        for watch in control_timers.values():
            if watch.is_alive(): watch.join(timeout=10)
        report['control_diagnostics'] = {'enabled':args.diagnose_control,'captures':[p.name for p in work.glob('slow-control-*.log')]}
        # Fault injection can abort before instrumentation switches the peer
        # back on. Leave the persistent disposable fixture ready for a rerun.
        try:
            request = urllib.request.Request('http://127.0.0.1:18080/peer?state=on', data=b'', method='POST')
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200
        except (OSError, AssertionError) as error:
            report['fixture_peer_cleanup'] = type(error).__name__
        nft_command('delete', 'table', 'inet', fault_table, check=False)
        try: adb('shell', 'svc', 'wifi', 'enable')
        except subprocess.CalledProcessError: pass
        try:
            adb("shell", "am", "broadcast", "-a", "org.amnezia.routingtest.POLICY", "-n", admin, "--es", "mode", "off")
            adb("shell", "dpm", "remove-active-admin", admin)
        except subprocess.CalledProcessError:
            report["policy_cleanup"] = "FAIL"
        (work / "android-acceptance.json").write_text(json.dumps(report, indent=2) + "\n")
        for label, command in {
            "routes": ("shell", "ip", "route", "show", "table", "all"),
            "rules": ("shell", "ip", "rule"),
            "connectivity": ("shell", "dumpsys", "connectivity"),
            "service-errors": ("logcat", "-d", "-s", "AndroidRuntime:E", "AmneziaVpnService:E", "Go:E", "libc:F"),
        }.items():
            try:
                (work / (label + ".log")).write_text(adb(*command))
            except subprocess.CalledProcessError:
                pass
        adb("shell", "am", "force-stop", PACKAGE)
        for suffix in ('a','b'):
            subprocess.run(['adb','shell','am','force-stop','org.amnezia.routingprobe.'+suffix],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        for process in probe_processes:
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate(); process.wait(timeout=5)
        for log in probe_logs: log.close()
        for probe_apk in probe_apks: probe_apk.unlink(missing_ok=True)
        # Always remove the throwaway keys and the fixture-bearing test APKs.
        for path in (key, target, instrument, aligned, unsigned):
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
