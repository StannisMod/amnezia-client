"""Run the real HEV loop with a socket-pair UTUN fixture, not a physical VPN."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    entries = list(args.source.glob("**/src/hev-socks5-tunnel.c"))
    if len(entries) != 1:
        parser.error("expected exactly one HEV source tree in the existing Conan source cache")
    source_root = entries[0].parent.parent
    if source_root.resolve() in args.work.resolve().parents:
        parser.error("work directory must not be inside the cached source")
    args.work.mkdir(parents=True, exist_ok=False)
    source = args.work.resolve() / "source"
    shutil.copytree(source_root, source, symlinks=True)
    spec = importlib.util.spec_from_file_location(
        "hev_native_dns", root / "recipes/hev-socks5-tunnel/native_dns_filter.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    entry = source / "src/hev-socks5-tunnel.c"
    entry.write_text(overlay.prepare(entry.read_text()))
    header = source / "src/hev-main.h"
    header.write_text(overlay.prepare_header(header.read_text()))
    sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    env = {**os.environ, "SDKROOT": sdk, "CC": "xcrun --sdk macosx clang", "AR": "ar",
           "CFLAGS": f"-O2 -isysroot {sdk}", "LDFLAGS": f"-isysroot {sdk}"}
    subprocess.run(["make", "-j2", "static"], cwd=source, env=env, check=True, timeout=300)
    libraries = ["bin/libhev-socks5-tunnel.a", "third-part/lwip/bin/liblwip.a",
                 "third-part/yaml/bin/libyaml.a", "third-part/hev-task-system/bin/libhev-task-system.a"]
    executable = args.work.resolve() / "reader-test"
    subprocess.run(["xcrun", "--sdk", "macosx", "clang", "-std=c11", "-D_DARWIN_C_SOURCE",
                    "-Wall", "-Wextra", "-Werror", "-I", str(source / "src"),
                    str(root / "client/tests/native-hev-reader/main.c"),
                    *[str(source / name) for name in libraries], "-lpthread", "-lm",
                    "-o", str(executable)], env=env, check=True, timeout=60)
    subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    main()
