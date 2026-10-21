#!/usr/bin/env python3
"""Record compilation separately from installer, signing and VPN acceptance."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return (result.stdout or result.stderr).strip()[:2000]
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def main():
    target = sys.argv[1]
    outcome = os.environ.get("BUILD_OUTCOME", "")
    status = "PASS" if outcome == "success" else "FAIL" if outcome == "failure" else "NOT RUN"
    artifacts = []
    suffixes = {"linux": {".run"}, "windows": {".msi", ".exe"}, "android": {".apk"}, "ios": {".ipa"}}[target]
    root = Path("deploy/build")
    if root.exists():
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in suffixes:
                # Restrict Windows to installers, not embedded helper EXEs.
                if target == "windows" and path.parent != root:
                    continue
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                artifacts.append({"path": path.as_posix(), "sha256": digest.hexdigest(), "bytes": path.stat().st_size})
    report = {
        "schema_version": 1,
        "source_sha": command("git", "rev-parse", "HEAD"),
        "platform": target,
        "abi": os.environ.get("ROUTING_ABI", platform.machine()),
        "host": platform.platform(),
        "client_baseline_compile": status,
        "routing_core_linked_into_client": target == "android" and os.environ.get("ROUTING_PAYLOAD_OUTCOME") == "success",
        "routing_core_packaged_with_service": target in {"linux", "windows"} and any(root.rglob("amnezia-routing.exe" if target == "windows" else "amnezia-routing")),
        "native_vpn_acceptance": "NOT RUN",
        "installer_smoke_test": "NOT RUN",
        "signing": "BLOCKED" if target == "ios" else "debug" if target == "android" else "unsigned",
        "signing_blocker": "Apple app and Network Extension identities/profiles are required" if target == "ios" else None,
        "tools": {"cmake": command("cmake", "--version"), "conan": command("conan", "--version"), "go": command("go", "version")},
        "artifacts": artifacts,
        "workflow_run": os.environ.get("GITHUB_RUN_ID"),
    }
    Path("routing-build-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
