#!/usr/bin/env python3
"""Bounded real Linux Xray/QtRO stop regression in a private resolved namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--service", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--peer", type=Path, help="Use an already linked actual-client GUI test")
parser.add_argument("--install-build", type=Path, help="Install current CMake tree into disposable /opt/AmneziaVPN")
parser.add_argument("--debugger", action="store_true", help="Capture host-cached GDB stack; always exits nonzero")
args = parser.parse_args()
if os.environ.get("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace":
    raise RuntimeError("requires isolated namespace")
links = json.loads(subprocess.check_output(["ip", "-j", "link"], text=True))
if {link["ifname"] for link in links} != {"lo"}:
    raise RuntimeError("requires --network none")
cgroup = Path("/sys/fs/cgroup")
for line in Path("/proc/self/cgroup").read_text().splitlines():
    if line.startswith("0::"):
        candidate = cgroup / line[3:].lstrip("/")
        if (candidate / "cpu.max").is_file():
            cgroup = candidate
quota, period = map(int, (cgroup / "cpu.max").read_text().split())
memory = int((cgroup / "memory.max").read_text())
swap = int((cgroup / "memory.swap.max").read_text())
if quota > 2 * period or memory > 4 * 1024**3 or swap:
    raise RuntimeError("requires 2 CPU / 4 GiB / zero extra swap")
print(f"Measured fixture cgroup: cpu={quota}/{period}, memory={memory}, swap={swap}", flush=True)
if args.install_build:
    subprocess.run(["cmake", "--install", str(args.install_build), "--prefix", "/opt/AmneziaVPN"], check=True)
out = args.output
out.mkdir(exist_ok=False)
root = Path(__file__).resolve().parents[2]
if not args.peer:
    subprocess.run(["cmake", "-S", str(root / "tests/xray-service-stop"), "-B", str(out / "build"),
                    "-DCMAKE_PREFIX_PATH=/opt/Qt/6.10.1/gcc_64"], check=True)
    subprocess.run(["cmake", "--build", str(out / "build"), "--parallel", "2"], check=True)
for binary in (args.service, args.service.parent / "tun2socks"):
    print(binary.name, hashlib.sha256(binary.read_bytes()).hexdigest(), flush=True)
if args.install_build:
    provenance = {}
    for binary in (args.service, args.service.parent / "tun2socks", args.service.parent / "AmneziaVPN"):
        elf = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
        static = "INTERP" not in elf and "DYNAMIC" not in elf
        dependencies = ("static ELF: no INTERP or DYNAMIC program header"
                        if static else subprocess.check_output(["ldd", str(binary)], text=True))
        if "not found" in dependencies:
            raise RuntimeError("unresolved installed binary dependency")
        provenance[binary.name] = {
            "path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "loaded_dependencies": dependencies}
    unit = Path("/opt/AmneziaVPN/AmneziaVPN.service").read_text()
    if "ExecStart=" + str(args.service) not in unit:
        raise RuntimeError("installed service path differs from shipped unit")
    provenance["unit"] = unit
    provenance["scope"] = "installed-layout runtime; no systemd manager in this container"
    (out / "installed-provenance.json").write_text(json.dumps(provenance, indent=2))
with (out / "service.log").open("w") as log:
    service = subprocess.Popen([str(args.service), "--console"], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 5
        while not Path("/tmp/local:AmneziaVpnIpcInterface").exists():
            if service.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("service readiness")
            time.sleep(.05)
        environment = dict(os.environ, AMNEZIA_SERVICE_PID=str(service.pid))
        command = [str(args.peer or out / "build/xray_service_stop")]
        if args.debugger:
            command = ["/host/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                       "--library-path", "/host/usr/lib/x86_64-linux-gnu",
                       "/host/usr/bin/gdb", "--data-directory=/host/usr/share/gdb",
                       "-nx", "-batch", "-ex", "run", "-ex", "thread apply all bt",
                       "-ex", "quit 99", "--args", *command]
            environment["PYTHONHOME"] = "/host/usr"
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=60, env=environment)
        (out / "peer.log").write_text(result.stdout)
        print(result.stdout, flush=True)
        result.check_returncode()
    finally:
        service.terminate()
        try:
            service.wait(timeout=5)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait(timeout=5)
