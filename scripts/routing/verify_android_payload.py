#!/usr/bin/env python3
"""Verify the final APK contains both legacy and routed JNI in one payload."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    args = parser.parse_args()
    from verify_notices import apk as verify_notices
    records = []
    for apk in sorted(args.build_dir.rglob("*.apk")):
        with zipfile.ZipFile(apk) as archive:
            libraries = [name for name in archive.namelist() if name.endswith("/libwg-go.so")]
            if not libraries:
                continue
            notice_result = verify_notices(apk)
            for name in libraries:
                payload = archive.read(name)
                with tempfile.TemporaryDirectory() as directory:
                    binary = Path(directory) / "libwg-go.so"
                    binary.write_bytes(payload)
                    symbols = subprocess.check_output([str(args.readelf), "--dyn-syms", "-W", str(binary)], text=True)
                    expected = ["Java_org_amnezia_awg_GoBackend_awgTurnOn", "Java_org_amnezia_awg_RoutingBackend_validate", "Java_org_amnezia_awg_RoutingBackend_start", "Java_org_amnezia_awg_RoutingBackend_stop", "Java_org_amnezia_awg_RoutingBackend_stats"]
                    for symbol in expected:
                        if not re.search(r"\b" + re.escape(symbol) + r"$", symbols, re.M):
                            raise SystemExit(f"Missing {symbol} in {apk}:{name}")
                    if len(re.findall(r"\b_cgo_topofstack$", symbols, re.M)) != 1:
                        raise SystemExit("Unexpected Go runtime symbol count in AWG payload")
                    layout = subprocess.check_output([str(args.readelf), "-l", "-W", str(binary)], text=True)
                    loads = [line for line in layout.splitlines() if line.strip().startswith("LOAD")]
                    if not loads or any(int(line.split()[-1], 0) < 16384 for line in loads):
                        raise SystemExit("AWG payload is not aligned for Android 16 KB pages")
                records.append({"apk": str(apk), "library": name, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload), "routing_notices": notice_result})
    if not records:
        raise SystemExit("No packaged AWG native library found in the built APKs")
    Path("android-routing-payloads.json").write_text(json.dumps(records, indent=2) + "\n")
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
