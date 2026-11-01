#!/usr/bin/env python3
"""Incremental emulator payload; preserves the packaged production Kotlin/Qt.

This is test input, not a full-client build or distributable release artifact.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-sha", required=True)
    args = parser.parse_args()
    # A native-only update is valid only while production Android sources and
    # protocol configuration serialization match the packaged client baseline.
    changed = subprocess.check_output(["git", "diff", "--name-only", args.baseline_sha, "HEAD", "--", "client/android", "client/platforms/android"], text=True)
    assert not changed.strip(), "Android host changed; use an APK rebuilt from this commit"
    target = "lib/x86_64/libwg-go.so"
    with zipfile.ZipFile(args.apk) as original, zipfile.ZipFile(args.output, "w") as updated:
        assert target in original.namelist()
        for entry in original.infolist():
            if entry.filename.startswith("META-INF/"):
                continue  # the disposable driver signs both APKs consistently
            data = args.native.read_bytes() if entry.filename == target else original.read(entry)
            updated.writestr(entry, data)
    report = {"mode": "incremental-emulator-only", "packaged_host_sha": args.baseline_sha,
              "native_source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "baseline_apk_sha256": hashlib.sha256(args.apk.read_bytes()).hexdigest()}
    args.output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
