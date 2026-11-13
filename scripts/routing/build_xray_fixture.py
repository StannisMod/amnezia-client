#!/usr/bin/env python3
"""Build the lab Xray CLI from the Android libxray recipe's verified source pin."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    recipe = (ROOT/"recipes/amnezia-libxray/conanfile.py").read_text()
    version = re.search(r'^    version = "([^"]+)"$', recipe, re.M)
    digest = re.search(r'sha256="([0-9a-f]{64})"', recipe)
    assert version and digest, "libxray source pin changed; update the fixture builder explicitly"
    version, digest = version[1], digest[1]
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    archive = work/"libxray-source.zip"
    url = f"https://github.com/amnezia-vpn/amnezia-libxray/archive/refs/tags/v{version}.zip"
    if archive.exists():
        data = archive.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(32*1024*1024+1)
    assert len(data) <= 32*1024*1024 and hashlib.sha256(data).hexdigest() == digest, "libxray archive checksum mismatch"
    archive.write_bytes(data)
    module = work/"module"; module.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        # Read only two exact members; never extract arbitrary archive paths.
        for name in ("go.mod", "go.sum"):
            (module/name).write_bytes(source.read(f"amnezia-libxray-{version}/{name}"))
    definition = (module/"go.mod").read_text()
    core = re.search(r'^replace github.com/xtls/xray-core => (github.com/amnezia-vpn/amnezia-xray-core) (\S+)$', definition, re.M)
    assert core, "Android Xray fork pin is missing"
    environment = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN="local", GOTELEMETRY="off")
    output = args.output.resolve(); output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([args.go, "build", "-mod=readonly", "-buildvcs=false", "-ldflags=-checklinkname=0", "-o", str(output),
                    "github.com/xtls/xray-core/main"], cwd=module, env=environment, check=True)
    description = subprocess.check_output([str(output), "version"], text=True).strip()
    record = {"libxray_version": version, "source_archive_url": url, "source_archive_sha256": digest,
              "xray_module": core[1], "xray_module_version": core[2],
              "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "version_output": description,
              "go_version": subprocess.check_output([args.go, "version"], text=True).strip(),
              "purpose": "disposable test peer; not a client payload"}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(record, indent=2)+"\n")
    print(description)


if __name__ == "__main__":
    main()
