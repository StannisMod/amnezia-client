#!/usr/bin/env python3
"""Offline native OpenVPN rebuild from an existing configured Conan source.

Never invokes Conan or fetches packages; the original cache remains read-only.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


def native_dependencies(binary):
    output = subprocess.check_output(["ldd", str(binary)], text=True, stderr=subprocess.STDOUT)
    if "not found" in output:
        raise RuntimeError(f"Unresolved cached native dependency: {output}")
    dependencies = {}
    for line in output.splitlines():
        match = re.match(r"\s*(\S+) => (/\S+) \(", line)
        if match:
            name, path = match.groups()
        elif line.lstrip().startswith("/"):
            path = line.split()[0]
            name = Path(path).name
        else:
            continue  # The kernel-provided VDSO has no backing library file.
        resolved = Path(path).resolve()
        dependencies[name] = {
            "path": str(resolved),
            "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        }
    if not dependencies:
        raise RuntimeError("No measurable native dependencies found")
    return dependencies


def validate_native_option(baseline, candidate):
    def invoke(binary, arguments):
        return subprocess.run([str(binary), *arguments], capture_output=True, text=True, timeout=5)

    before = invoke(baseline, ["--help"])
    after = invoke(candidate, ["--help"])
    if after.returncode != before.returncode or "--management-external-dns" not in after.stdout:
        raise RuntimeError("Native opt-in help/exit behavior is inconsistent with the baseline")
    results = {"help_exit": after.returncode, "invalid_configurations": {}}
    # These fail in option validation before TLS/file loading or TUN startup.
    # /dev/null is not used to bypass any certificate validation.
    base = ["--dev", "null", "--tls-client", "--remote", "127.0.0.1", "31999",
            "--ca", "/dev/null", "--management-external-dns"]
    for label, extra in (
        ("missing-management", []),
        ("nonlocal-management", ["--management", "192.0.2.1", "31998", "--management-client"]),
        ("non-client-management", ["--management", "127.0.0.1", "31998"]),
    ):
        result = invoke(candidate, base + extra)
        if result.returncode == 0 or "requires a local IPv4 management client" not in result.stdout + result.stderr:
            raise RuntimeError(f"Native {label} did not fail at the expected validation boundary: {result.stdout}{result.stderr}")
        results["invalid_configurations"][label] = result.returncode
        print(f"PASS: actual native option validation {label}, exit {result.returncode}", flush=True)
    # Use a valid executable so this reaches ownership validation rather than
    # the earlier native access(X_OK) check. The guard must reject before exec.
    scripted = invoke(candidate, base + ["--management", "127.0.0.1", "31998",
                                        "--management-client", "--up", "/bin/true"])
    if scripted.returncode == 0 or "cannot share DNS ownership with caller scripts" not in scripted.stdout + scripted.stderr:
        raise RuntimeError(f"A competing caller script was not refused at the expected boundary: "
                           f"exit={scripted.returncode}\n{scripted.stdout}{scripted.stderr}")
    results["competing_script_exit"] = scripted.returncode
    print("PASS: actual native option validation rejects competing caller script", flush=True)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cached-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("openvpn_dns_overlay", repo / "recipes/openvpn/native_dns.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    flags = shlex.split(subprocess.check_output(
        [str(args.cached_root / "build-release/config.status"), "--config"], text=True))
    baseline = args.cached_root / "build-release/src/openvpn/openvpn"
    baseline_dependencies = native_dependencies(baseline)
    with tempfile.TemporaryDirectory(prefix="cached-openvpn-dns-") as temporary:
        source = Path(temporary) / "source"
        shutil.copytree(args.cached_root, source,
                        ignore=shutil.ignore_patterns("build-release", "autom4te.cache", ".git"))
        overlay.apply(source)
        build = Path(temporary) / "build"
        build.mkdir()
        subprocess.run([str(source / "configure"), *flags, f"--srcdir={source}"], cwd=build, check=True)
        subprocess.run(["make", "-j2"], cwd=build, check=True)
        binary = build / "src/openvpn/openvpn"
        args.output.mkdir(parents=True, exist_ok=False)
        shutil.copy2(binary, args.output / "openvpn")
        report = {
            "cached_source": str(args.cached_root),
            "configure_arguments": flags,
            "network": "none (enforced by caller container)",
            "new_packages": False,
            "baseline_dependencies": baseline_dependencies,
            "validation": "pending",
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "overlay_sha256": hashlib.sha256((repo / "recipes/openvpn/native_dns.py").read_bytes()).hexdigest(),
            "helper_sha256": hashlib.sha256((repo / "recipes/openvpn/amnezia_dns.h").read_bytes()).hexdigest(),
            "scope": "native Linux offline full rebuild; not installed-service or other-platform runtime acceptance",
        }
        (args.output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
        try:
            subprocess.run([str(binary), "--version"], check=True)
            candidate_dependencies = native_dependencies(binary)
            report["candidate_dependencies"] = candidate_dependencies
            report["existing_native_dependencies_unchanged"] = candidate_dependencies == baseline_dependencies
            if candidate_dependencies != baseline_dependencies:
                raise RuntimeError("The native OpenVPN dependency closure changed")
            report["native_option_validation"] = validate_native_option(baseline, binary)
        except Exception as error:
            report.update(validation="failed", error=str(error))
            (args.output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
            raise
        report["validation"] = "passed"
        (args.output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
        print("PASS: full native OpenVPN rebuild offline with cached dependency paths; binary/provenance preserved")


if __name__ == "__main__":
    main()
