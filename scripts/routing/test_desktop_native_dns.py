"""Check the native desktop DNS overlay against an existing pinned source cache.

No source/package download and no interface changes. The optional C fixture
requires the caller's disposable namespace and assigned dns-fixture address.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess


def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        yield value
        text = text[end:]


def graph(source, env):
    result = subprocess.check_output(
        ["go", "list", "-mod=readonly", "-deps", "-json", "."],
        cwd=source, env=env, text=True, timeout=300)
    modules = {}
    for package in objects(result):
        module = package.get("Module")
        if module and not module.get("Main"):
            replacement = module.get("Replace", {})
            modules[module["Path"]] = [module.get("Version"), replacement.get("Path"),
                                       replacement.get("Version")]
    return modules


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--native-fixture", action="store_true")
    args = parser.parse_args()
    if args.native_fixture and os.environ.get("AMNEZIA_DNS_LOCAL_INTERFACE_TEST") != "isolated-namespace":
        parser.error("native fixture requires an explicitly owned isolated namespace")
    root = Path(__file__).resolve().parents[2]
    args.work.mkdir(parents=True, exist_ok=False)
    stage = args.work.resolve()
    for name in ("main.go", "Makefile", "go.mod", "go.sum"):
        shutil.copy2(args.source / name, stage / name)
    spec = importlib.util.spec_from_file_location(
        "native_dns_overlay", root / "recipes/amnezia-xray-bindings/native_dns.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    env = {**os.environ, "GOPROXY": "off"}
    before = graph(stage, env)
    overlay.prepare(stage, root / "native/routing/nativedns",
                    root / "native/routing/desktopbridge/native_dns.go")
    # Idempotence must not add registrations/dependencies on repeated builds.
    first = (stage / "go.mod").read_bytes()
    overlay.prepare(stage, root / "native/routing/nativedns",
                    root / "native/routing/desktopbridge/native_dns.go")
    assert (stage / "go.mod").read_bytes() == first
    env["GOFLAGS"] = "-mod=readonly -tags=amnezia_native_dns"
    after = graph(stage, env)
    assert all(after.get(key) == value for key, value in before.items()), "native dependency graph changed"
    assert set(after) - set(before) == {overlay.MODULE}, "unexpected additional dependencies"
    (stage / "native-dependency-graph.json").write_text(
        json.dumps({"compiled_modules_before": before, "compiled_modules_after": after}, indent=2) + "\n")
    subprocess.run(["go", "build", "-buildmode=c-archive", "-o", "amnezia_xray.a", "."],
                   cwd=stage, env=env, check=True, timeout=300)
    print("PASS: compiled native Xray dependency versions unchanged; DNS C ABI compiled in the same archive",
          flush=True)
    if args.native_fixture:
        subprocess.run(["cc", "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
                        "-I", str(stage), str(root / "native/routing/desktopbridge/native_dns_client.c"),
                        str(stage / "amnezia_xray.a"), "-lpthread", "-ldl", "-lm", "-lresolv",
                        "-o", str(stage / "dns-client")], check=True, timeout=60)
        subprocess.run([str(stage / "dns-client")], env=env, check=True, timeout=30)


if __name__ == "__main__":
    main()
