"""Prepare the single existing AWG/XRay archive with the pinned routing core."""
from pathlib import Path
import shutil


def prepare_module(core, destination):
    core, destination = Path(core).resolve(), Path(destination).resolve()
    local = destination / "amnezia-routing"
    if local.exists():
        shutil.rmtree(local)
    shutil.copytree(core, local, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    bridge = core / "applebridge"
    for source, target in (("module.mod", "go.mod"), ("module.sum", "go.sum"),
                           ("routing_apple.go", "routing_apple.go"),
                           ("amnezia_routing.h", "amnezia_routing.h")):
        shutil.copy2(bridge / source, destination / target)
    makefile = destination / "Makefile"
    text = makefile.read_text()
    original = "go build -ldflags=-w"
    if text.count(original) != 1:
        raise RuntimeError("Unexpected AWG Apple build entry point")
    text = text.replace(original, "go build -mod=readonly -tags with_gvisor,amnezia_apple_bridge -ldflags=-w")
    makefile.write_text(text)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--module", type=Path, required=True)
    args = parser.parse_args()
    prepare_module(args.core, args.module)
