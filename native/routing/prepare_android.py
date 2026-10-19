"""Overlay the pinned shared core into AWG's existing Android Go payload.

Used by the Conan recipe and the standalone native CI lane. It deliberately
creates one libwg-go build; it never builds/loads another Go shared library.
"""
from pathlib import Path
import re
import shutil


GO_VERSION = "go1.27.1"


def prepare_module(core, destination):
    core, destination = Path(core).resolve(), Path(destination).resolve()
    local_module = destination / "amnezia-routing"
    if local_module.exists():
        shutil.rmtree(local_module)
    shutil.copytree(core, local_module, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    module = (core / "go.mod").read_text()
    module = module.replace(
        "module github.com/StannisMod/amnezia-client/native/routing",
        "module github.com/amnezia-vpn/amneziawg-android", 1,
    )
    module += ("\nrequire github.com/StannisMod/amnezia-client/native/routing v0.0.0\n"
               "replace github.com/StannisMod/amnezia-client/native/routing => ./amnezia-routing\n")
    (destination / "go.mod").write_text(module)
    (destination / "go.sum").write_text((core / "go.sum").read_text())
    for path in (core / "androidbridge").iterdir():
        if path.suffix in {".go", ".c", ".h"}:
            shutil.copy2(path, destination / path.name)


def prepare_runtime(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if (source / "VERSION").read_text().splitlines()[0] != GO_VERSION:
        raise RuntimeError("The routed AWG native build requires exactly Go 1.27.1")
    marker = destination / ".amnezia-routing-boottime"
    if marker.exists() and marker.read_text() == GO_VERSION:
        return destination
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=True)
    # Preserve AWG's suspend-aware timers with a patch validated against the
    # pinned Go source. The old upstream Go-1.20 diff no longer fits Go 1.27.
    for arch, expected in {"386": 2, "amd64": 1, "arm": 1, "arm64": 1}.items():
        path = destination / "src/runtime" / f"sys_linux_{arch}.s"
        text = path.read_text()
        if arch in {"arm", "arm64"}:
            text, count = re.subn(r"(#define CLOCK_MONOTONIC[ \t]+)1\b", r"\g<1>7", text)
        else:
            text, count = re.subn(r"\$1(,[^\n]*// CLOCK_MONOTONIC)", r"$7\1", text)
        if count != expected:
            raise RuntimeError(f"Unexpected Go CLOCK_BOOTTIME patch context for {arch}")
        path.write_text(text.replace("CLOCK_MONOTONIC", "CLOCK_BOOTTIME"))
    marker.write_text(GO_VERSION)
    return destination


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--go-root", type=Path, required=True)
    parser.add_argument("--patched-go-root", type=Path, required=True)
    args = parser.parse_args()
    prepare_module(args.core, args.module)
    print(prepare_runtime(args.go_root, args.patched_go_root))
