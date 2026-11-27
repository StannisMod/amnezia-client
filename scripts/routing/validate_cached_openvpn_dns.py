#!/usr/bin/env python3
"""Validate a preserved binary without rebuilding/relabeling its original report."""
import argparse
import hashlib
import json
from pathlib import Path
import build_cached_openvpn_dns as checks


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise RuntimeError("Refusing to overwrite an earlier validation report")
    original_path = args.candidate.with_name("manifest.json")
    original = json.loads(original_path.read_text())
    root = Path(__file__).resolve().parents[2]
    if original["binary_sha256"] != digest(args.candidate):
        raise RuntimeError("Preserved binary changed")
    for field, relative in (("overlay_sha256", "recipes/openvpn/native_dns.py"),
                             ("helper_sha256", "recipes/openvpn/amnezia_dns.h")):
        if original[field] != digest(root / relative):
            raise RuntimeError("Preserved binary does not match the current native source")
    result = checks.validate_native_option(args.baseline, args.candidate)
    before, after = checks.native_dependencies(args.baseline), checks.native_dependencies(args.candidate)
    if before != after:
        raise RuntimeError("Native dependency closure changed")
    report = {
        "validation": "passed", "candidate": str(args.candidate),
        "binary_sha256": original["binary_sha256"],
        "overlay_sha256": original["overlay_sha256"], "helper_sha256": original["helper_sha256"],
        "checks_source_sha256": digest(Path(checks.__file__)),
        "native_option_validation": result,
        "existing_native_dependencies_unchanged": True, "dependencies": after,
        "original_manifest": str(original_path), "original_validation": original.get("validation"),
        "scope": "Same preserved Linux binary; corrected executable fixture. Not TLS tunnel/installed-service acceptance.",
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: exact preserved binary/current native source; loaded dependencies unchanged; original manifest retained", flush=True)


if __name__ == "__main__":
    main()
