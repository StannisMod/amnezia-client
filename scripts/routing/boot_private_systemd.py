#!/usr/bin/env python3
"""Boot cached systemd as PID 1, confined to Docker's private bounded cgroup."""
import os
from pathlib import Path
import shutil
import subprocess

if os.getpid() != 1 or Path("/proc/self/cgroup").read_text().strip() != "0::/":
    raise RuntimeError("requires private PID/cgroup namespaces")
if os.environ.get("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace":
    raise RuntimeError("requires caller-owned isolated namespace")
private = Path("/run/amnezia-private-cgroup")
private.mkdir()
subprocess.run(["mount", "-t", "cgroup2", "-o", "rw,nsdelegate", "none", str(private)], check=True)
subprocess.run(["mount", "--bind", str(private), "/sys/fs/cgroup"], check=True)
cgroup = Path("/sys/fs/cgroup")
quota, period = map(int, (cgroup / "cpu.max").read_text().split())
memory = int((cgroup / "memory.max").read_text())
swap = int((cgroup / "memory.swap.max").read_text())
if quota > 2 * period or memory > 4 * 1024**3 or swap:
    raise RuntimeError("requires 2 CPU / 4 GiB / zero extra swap")
print(f"Private systemd parent: cpu={quota}/{period}, memory={memory}, swap={swap}", flush=True)
if Path("/usr/local/lib/amnezia-fixture-os/manifest.json").is_file():
    Path("/etc/ld.so.conf.d/amnezia-fixture-os.conf").write_text("/usr/local/lib/amnezia-fixture-os\n")
    subprocess.run(["ldconfig"], check=True)
unit = Path("/opt/AmneziaVPN/AmneziaVPN.service")
if os.environ.get("AMNEZIA_SYSTEMD_INSTALLER") != "1":
    shutil.copy2(unit, "/etc/systemd/system/AmneziaVPN.service")
if os.environ.get("AMNEZIA_SYSTEMD_DNS_FIXTURE") == "1":
    runtime = Path("/run/amnezia-private-resolved")
    runtime.mkdir()
    (runtime / "bus.conf").write_text(
        '<busconfig><type>system</type><listen>unix:path=/run/amnezia-private-resolved/bus</listen>'
        '<auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/>'
        '<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    subprocess.run(["sh", "-c", "getent passwd systemd-resolve >/dev/null || "
                    "useradd --system --no-create-home --shell /usr/sbin/nologin systemd-resolve"], check=True)
    Path("/run/systemd/resolve").mkdir(parents=True, exist_ok=True)
    shutil.chown("/run/systemd/resolve", user="systemd-resolve", group="systemd-resolve")
    loader = "/host/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    libraries = "/host/usr/lib/x86_64-linux-gnu:/host/usr/lib/x86_64-linux-gnu/systemd"
    Path("/etc/systemd/system/AmneziaFixtureBus.service").write_text(
        "[Service]\nExecStart=" + loader + " --library-path " + libraries
        + " /host/usr/bin/dbus-daemon --config-file=/run/amnezia-private-resolved/bus.conf --nofork\n")
    Path("/etc/systemd/system/AmneziaFixtureResolved.service").write_text(
        "[Unit]\nRequires=AmneziaFixtureBus.service\nAfter=AmneziaFixtureBus.service\n"
        "[Service]\nEnvironment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/amnezia-private-resolved/bus\n"
        "ExecStart=" + loader + " --library-path " + libraries + " /host/usr/lib/systemd/systemd-resolved\n")
    dropin = Path("/etc/systemd/system/AmneziaVPN.service.d")
    dropin.mkdir()
    (dropin / "dns-fixture.conf").write_text(
        "[Unit]\nRequires=AmneziaFixtureResolved.service\nAfter=AmneziaFixtureResolved.service\n"
        "[Service]\nEnvironment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/amnezia-private-resolved/bus\n")
os.environ["container"] = "docker"
os.execv("/sbin/init", ["/sbin/init", "--log-target=console"])
