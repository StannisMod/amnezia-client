#!/usr/bin/env python3
"""Measure the real installed OpenVPN closure; never repair the installation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from build_cached_openvpn_dns import native_dependencies

parser = argparse.ArgumentParser()
parser.add_argument("--native", type=Path, required=True)
parser.add_argument("--prefix", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
binary = args.prefix / "bin/openvpn"
manifest = json.loads((args.prefix / "bin/openvpn-runtime.json").read_text())
source_hash = hashlib.sha256(args.native.read_bytes()).hexdigest()
installed_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
if manifest["source_sha256"] != source_hash or manifest["deployed_sha256"] != installed_hash:
    raise RuntimeError("Installed executable does not match production deployment manifest")
baseline = native_dependencies(args.native)
installed = native_dependencies(binary)
if baseline.keys() != installed.keys():
    raise RuntimeError("Installed native dependency set changed")
for name, library in baseline.items():
    if installed[name]["sha256"] != library["sha256"]:
        raise RuntimeError("Installed native dependency bytes changed: " + name)
    if name in manifest["libraries"]:
        expected = (args.prefix / "bin/openvpn-libs" / name).resolve()
        if Path(installed[name]["path"]).resolve() != expected:
            raise RuntimeError("Installed native dependency escaped its private closure: " + name)
version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=5)
if version.returncode:
    raise RuntimeError(version.stdout + version.stderr)
service = native_dependencies(args.prefix / "bin/AmneziaVPN-service")
args.output.write_text(json.dumps({
    "validation": "passed", "source_sha256": source_hash, "installed_sha256": installed_hash,
    "baseline": baseline, "installed": installed, "service": service,
    "version": version.stdout + version.stderr,
    "scope": "unmodified production CMake install; no post-install library repairs",
}, indent=2))
print(f"PASS: installed OpenVPN runs with all {len(installed)} frozen dependency hashes unchanged", flush=True)
print("Native libcrypto:", installed.get("libcrypto.so.3"), flush=True)
print("Service libcrypto:", service.get("libcrypto.so.3"), flush=True)
