#!/usr/bin/env python3
"""Exercise the native DNS C ABI on Linux with the real Apple parent Go graph.

This is not an Apple SDK or native device test. All Go dependencies must
already be cached; the caller controls its resource/network sandbox.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    bridge = root / "native/routing/applebridge"
    args.work.mkdir(parents=True, exist_ok=False)
    stage = args.work.resolve()
    for source, target in (("module.mod", "go.mod"), ("module.sum", "go.sum"),
                           ("native_dns_apple.go", "native_dns_apple.go"),
                           ("amnezia_routing.h", "amnezia_routing.h")):
        shutil.copy2(bridge / source, stage / target)
    (stage / "amnezia-routing").symlink_to(root / "native/routing", target_is_directory=True)
    (stage / "main.go").write_text("package main\nfunc main() {}\n")
    env = {**os.environ, "GOPROXY": "off"}
    subprocess.run(["go", "build", "-mod=readonly", "-tags", "with_gvisor,amnezia_apple_bridge",
                    "-buildmode=c-archive", "-o", str(stage / "dnsbridge.a"), "."],
                   cwd=stage, env=env, check=True, timeout=300)
    feature_namespace = "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_POSIX_C_SOURCE=200809L"
    subprocess.run(["cc", "-std=c11", feature_namespace, "-Wall", "-Wextra", "-Werror",
                    "-I", str(stage), str(bridge / "tests/native_dns_client.c"),
                    str(stage / "dnsbridge.a"), "-lpthread", "-ldl", "-lm", "-o", str(stage / "client")],
                   check=True, timeout=60)
    subprocess.run([str(stage / "client")], check=True, timeout=30)


if __name__ == "__main__":
    main()
