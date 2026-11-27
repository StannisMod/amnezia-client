#!/usr/bin/env python3
"""Bounded offline Linux fixture orchestrator; never run in a host namespace."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*arguments, **kwargs):
    subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-output")
    parser.add_argument("--skip-native-build", action="store_true")
    parser.add_argument("--cached-openvpn", type=Path, required=True)
    args = parser.parse_args()
    if not args.skip_native_build and not args.native_output:
        parser.error("--native-output is required unless --skip-native-build is set")
    if os.environ.get("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace":
        raise RuntimeError("Requires caller-owned isolated namespace")
    links = json.loads(subprocess.check_output(["ip", "-j", "link"], text=True))
    if {item["ifname"] for item in links} != {"lo"}:
        raise RuntimeError("Requires --network none; refusing to touch host/other interfaces")
    quota, period = map(int, Path("/sys/fs/cgroup/cpu.max").read_text().split())
    memory = int(Path("/sys/fs/cgroup/memory.max").read_text())
    swap = int(Path("/sys/fs/cgroup/memory.swap.max").read_text())
    if quota > 2 * period or memory > 4 * 1024**3 or swap != 0:
        raise RuntimeError("Requires bounded 2 CPU / 4 GiB / zero extra swap")
    print(f"Measured fixture cgroup: cpu={quota}/{period}, memory={memory}, swap={swap}", flush=True)
    root = Path(__file__).resolve().parents[2]
    routing = root / "scripts/routing"
    runtime = args.cache / "native-desktop-dns-20261123-v5"
    qt = "-DCMAKE_PREFIX_PATH=/opt/Qt/6.10.1/gcc_64"
    with tempfile.TemporaryDirectory(prefix="openvpn-service-fixture-") as temporary:
        temporary = Path(temporary)
        session = temporary / "session"
        run("cmake", "-S", root / "tests/openvpn-dns-session", "-B", session, "-DCMAKE_BUILD_TYPE=Release", qt)
        run("cmake", "--build", session, "--parallel", "2")
        run("ctest", "--test-dir", session, "-V", "--output-on-failure")
        parent = temporary / "parent"
        parent.mkdir()
        (parent / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.25)\nproject(ImportedDnsConsumer LANGUAGES CXX)\n"
            "add_library(amnezia::xray-bindings STATIC IMPORTED GLOBAL)\n"
            f'set_target_properties(amnezia::xray-bindings PROPERTIES IMPORTED_LOCATION "{runtime}/amnezia_xray.a" '
            f'INTERFACE_INCLUDE_DIRECTORIES "{runtime}")\n'
            f"include_directories({root}/common/logger)\n"
            f"add_subdirectory({root}/tests/native-dns-transaction native-dns)\n")
        build = temporary / "native-build"
        run("cmake", "-S", parent, "-B", build, "-DCMAKE_BUILD_TYPE=Release", qt)
        run("cmake", "--build", build, "--parallel", "2")
        run("ip", "link", "add", "dns-fixture", "type", "dummy")
        run("ip", "addr", "add", "192.0.2.10/32", "dev", "dns-fixture")
        run("ip", "link", "set", "dns-fixture", "up")
        run("sh", root / "tests/native-dns-transaction/run-private-resolved.sh",
            "ctest", "--test-dir", build / "native-dns", "-V", "--output-on-failure")
        run("python3", routing / "check_openvpn_service_translation_units.py",
            "--build", args.cache / "build", "--native-include", runtime)
        run("python3", routing / "test_openvpn_native_dns_overlay.py",
            "--source", args.cache / "conan/p/openv431e37635ab6a/s")
        run("python3", routing / "test_openvpn_dns_handoff.py")
        if not args.skip_native_build:
            run("python3", routing / "build_cached_openvpn_dns.py", "--cached-root", args.cached_openvpn,
                "--output", args.evidence / args.native_output)


if __name__ == "__main__":
    main()
