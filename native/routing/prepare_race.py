#!/usr/bin/env python3
"""Prepare private dependency copies with the upstream ARM64 race CAS fix.

Only -race/arm64 builds compile the affected assembly. Do not edit GOMODCACHE
or change the production module graph to fix this diagnostic-only defect.
Upstream: google/gvisor@1b2946c4fa59c1a64643bce962140b5686062601.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

PINNED = {
    "gvisor.dev/gvisor": "v0.0.0-20231202080848-1f7806d17489",
    "github.com/sagernet/gvisor": "v0.0.0-20260727.0-sing-box-mod.1",
}
BROKEN = "\tMOVD new+16(FP), R1\n"
FIXED = "\tMOVD new+16(FP), R2\n"


def go(root, *args):
    return subprocess.run(["go", *args], cwd=root, text=True,
                          capture_output=True, check=True).stdout


def prepare(parent):
    root = Path(__file__).resolve().parent
    modules = []
    for name, version in PINNED.items():
        info = json.loads(go(root, "mod", "download", "-json", name))
        if info.get("Version") != version or not info.get("Dir"):
            raise RuntimeError(f"Review the race fix for changed dependency {name}")
        source = Path(info["Dir"])
        text = (source / "pkg/sync/race_arm64.s").read_text()
        if text.count(BROKEN) != 1 or "MOVD old+8(FP), R1" not in text:
            raise RuntimeError(f"Unexpected ARM64 CAS source in {name}")
        modules.append((name, source, text))
    # Verify the originals before copying; generated changes never enter the
    # shared module cache and remain separate from go.mod/go.sum in the repo.
    go(root, "mod", "verify")
    parent.mkdir(parents=True, exist_ok=True)
    private = Path(tempfile.mkdtemp(prefix="amnezia-race-", dir=parent)).resolve()
    modfile = private / "go.mod"
    shutil.copyfile(root / "go.mod", modfile)
    shutil.copyfile(root / "go.sum", private / "go.sum")
    replacements = []
    for index, (name, source, text) in enumerate(modules):
        destination = private / f"gvisor-{index}"
        shutil.copytree(source, destination)
        assembly = destination / "pkg/sync/race_arm64.s"
        assembly.chmod(0o644)
        assembly.write_text(text.replace(BROKEN, FIXED))
        replacements.append(f"-replace={name}={destination}")
    go(root, "mod", "edit", f"-modfile={modfile}", *replacements)
    return modfile


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Parent for a new private temporary directory")
    args = parser.parse_args()
    try:
        print(prepare(args.output))
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stdout + error.stderr) from error
