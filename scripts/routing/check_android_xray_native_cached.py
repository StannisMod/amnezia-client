#!/usr/bin/env python3
"""Offline native Xray checks/JNI build with one locked incremental workspace."""
import argparse
import hashlib
import importlib.util
import json
import os
import resource
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256
from prepare_cached_source import write_changed


def inputs(directory):
    return {str(p.relative_to(directory)): sha256(p) for p in directory.rglob("*")
            if p.is_file() and not p.is_symlink() and
            (p.suffix == ".go" or p.name in ("go.mod", "go.sum"))}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cache-root", type=Path, default=Path("/work/lab-cache"))
    p.add_argument("--upstream", type=Path, required=True)
    p.add_argument("--engine", type=Path, required=True)
    p.add_argument("--tools", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--go-root", type=Path, default=Path("/cache/conan/p/go38a90af33defe/p"))
    p.add_argument("--bind", action="store_true")
    p.add_argument("--abi", choices=("arm64", "amd64"), default="arm64")
    p.add_argument("--runtime-probe", action="store_true")
    p.add_argument("--link-diagnostic-inputs", type=Path)
    p.add_argument("--retry-empty-incomplete-product", action="store_true")
    args = p.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.evidence.mkdir(parents=True, exist_ok=False)
    def evidence_json(name, value):
        path = args.evidence / name
        atomic_json(path, value)
        path.chmod(0o644)
    support = ROOT / "recipes/amnezia-libxray"
    recipe = hashlib.sha256((sha256(support / "native_dns.py") + sha256(args.upstream / "go.mod")
                             + sha256(args.engine / "go.mod")).encode()).hexdigest()
    cache = Cache(args.cache_root)
    with cache.workspace("android-xray-native-go127-ndk27-" + recipe[:12]) as work:
        module, manifest = work / "module", work / "ownership.json"
        bootstrap_bytes = 0
        if not module.exists():
            shutil.copytree(args.upstream, module)
            spec = importlib.util.spec_from_file_location("native_overlay", support / "native_dns.py")
            overlay = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(overlay)
            overlay.apply(module, args.engine, support, ROOT / "native/routing/nativedns")
            bootstrap_bytes = sum(path.stat().st_size for path in module.rglob("*")
                                  if path.is_file() and not path.is_symlink())
            atomic_json(manifest, inputs(module))
        if not manifest.exists():
            raise ValueError("Unmanifested native workspace retained")
        previous = json.loads(manifest.read_text())
        if inputs(module) != previous:
            raise ValueError("Native workspace changed outside the cache owner; retained")
        desired = {
            "native_dns_android.go": support / "native_dns_android.go",
            "native_dns_android_test.go": support / "native_dns_android_test.go",
            "amnezia-native-tun2socks/proxy/socks5/native_dns_test.go": support / "native_dns_socks_test.go",
        }
        if args.runtime_probe:
            desired["native_dns_runtime_probe.go"] = ROOT / "scripts/routing/android-xray-dns/runtime_probe.go"
        for path in (ROOT / "native/routing/nativedns").glob("*.go"):
            if not path.name.endswith("_test.go"):
                desired["amnezianativedns/" + path.name] = path
        written = 0
        for name, source in desired.items():
            written += write_changed(module / name, source.read_bytes())
        for name in previous:
            if (name.startswith("amnezianativedns/") or name == "native_dns_runtime_probe.go") and name not in desired:
                (module / name).unlink()  # Validated owned old source only.
        current = inputs(module)
        atomic_json(manifest, current)
        evidence_json("inputs.json", current)
        evidence_json("storage.json", {"source_bytes_written": bootstrap_bytes + written,
                    "incremental_source_bytes_written": written, "bootstrap_bytes_written": bootstrap_bytes,
                    "workspace": str(work), "tools_referenced_in_place": str(args.tools)})
        frozen = {name: (module / name).read_bytes() for name in ("go.mod", "go.sum")}
        env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOTELEMETRY="off",
                   GOMAXPROCS="2", GOMEMLIMIT="1536MiB", GOCACHE="/work/go-build-cache",
                   GOMODCACHE="/integration/modules", CGO_ENABLED="1")
        env["PATH"] = str(args.tools) + ":" + str(args.go_root / "bin") + ":" + env["PATH"]
        go = str(args.go_root / "bin/go")

        def run(name, command, **changes):
            stopped = threading.Event()
            measured = {"tmpfs_bytes_min_available": None, "memory_bytes_max_sampled": 0}
            def read_cgroup(name):
                path = Path("/sys/fs/cgroup") / name
                return path.read_text().strip() if path.exists() else None
            def sample():
                while not stopped.is_set():
                    fs = os.statvfs("/tmp")
                    free = fs.f_bavail * fs.f_frsize
                    measured["tmpfs_bytes_total"] = fs.f_blocks * fs.f_frsize
                    old = measured["tmpfs_bytes_min_available"]
                    measured["tmpfs_bytes_min_available"] = free if old is None else min(old, free)
                    memory = read_cgroup("memory.current")
                    if memory and memory.isdigit():
                        measured["memory_bytes_max_sampled"] = max(
                            measured["memory_bytes_max_sampled"], int(memory))
                    stopped.wait(0.01)
            observer = threading.Thread(target=sample, daemon=True)
            observer.start()
            try:
                result = subprocess.run(list(map(str, command)), cwd=module, env=dict(env, **changes),
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            finally:
                stopped.set()
                observer.join()
            measured.update(memory_peak=read_cgroup("memory.peak"),
                            memory_events=read_cgroup("memory.events"), exit=result.returncode)
            evidence_json(name + ".resources.json", measured)
            (args.evidence / (name + ".raw")).write_bytes(result.stdout)
            text = result.stdout.decode("utf-8", errors="replace")
            (args.evidence / (name + ".log")).write_text(text)
            print(text, flush=True)
            for path, data in frozen.items():
                if (module / path).read_bytes() != data:
                    raise RuntimeError("Pinned native declarations/sums changed")
            if result.returncode:
                raise SystemExit(result.returncode)

        tags = ["-tags=amnezia_native_dns_runtime_probe"] if args.runtime_probe else []
        compiler = "aarch64" if args.abi == "arm64" else "x86_64"
        diagnostic = args.link_diagnostic_inputs is not None
        if diagnostic and json.loads(args.link_diagnostic_inputs.read_text()) != current:
            raise ValueError("Link diagnostic sources differ from already exercised native runtime tests")
        if not diagnostic:
            run("android-compile", [go, "build", "-mod=readonly", "-p=1", *tags, "."],
            GOOS="android", GOARCH=args.abi,
            CC=f"/work/android-sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/{compiler}-linux-android24-clang")
        aliases = []
        try:
            for name in ("native_dns_android.go", "native_dns_android_test.go"):
                alias = module / name.replace("_android", "_host_harness")
                if alias.exists() or alias.is_symlink():
                    raise ValueError("Unknown host harness link retained")
                alias.symlink_to(name)
                aliases.append(alias)
            if not diagnostic:
                run("host-race", [go, "test", "-mod=readonly", "-p=1", "-race", "-count=1",
                "-timeout=90s", "-ldflags=-checklinkname=0",
                "-run", "TestAndroidNativeDNS|TestNativeDNSHandshakeCancellation", "-v", ".",
                "github.com/amnezia-vpn/amnezia-tun2socks/v2/proxy/socks5"],
                    GOOS="linux", GOARCH="amd64", CC="gcc")
        finally:
            for alias in aliases:
                alias.unlink()
        if inputs(module) != current:
            raise RuntimeError("Native tests changed owned source")
        if not args.bind:
            return
        runtime = {name: digest for name, digest in current.items() if not name.endswith("_test.go")}
        tool_hashes = {name: sha256(args.tools / name) for name in ("gomobile", "gobind")}
        identity = {"source": runtime, "tools": tool_hashes,
            "go": str(args.go_root), "ndk": "27.0.12077973", "api": 24, "abi": args.abi,
            "flags": "-w -s -buildid= -checklinkname=0 -trimpath"}
        if args.runtime_probe:
            identity["runtime_probe"] = True
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        product = cache.root / "products" / key
        label = "runtime-probe" if args.runtime_probe else "api-probe"
        aar, record = product / f"native-dns-{args.abi}-{label}.aar", product / "artifact.json"
        hit = record.exists()
        if hit:
            if sha256(aar) != json.loads(record.read_text())["sha256"]:
                raise ValueError("Cached JNI product differs; retained")
        else:
            if not (args.retry_empty_incomplete_product and product.is_dir() and not any(product.iterdir())):
                product.mkdir(parents=True, exist_ok=False)
            for name in tool_hashes:
                if not os.access(args.tools / name, os.X_OK):
                    raise ValueError("Existing cached native tool is not executable")
            run("jni-bind", [args.tools / "gomobile", "bind", f"-target=android/{args.abi}", "-androidapi=24", *tags,
                "-javapkg=org.amnezia.vpn.protocol.xray", "-o", aar,
                "-ldflags=-w -s -buildid= -checklinkname=0", "-trimpath", "."],
                GOOS="linux", GOARCH="amd64", CC="gcc", GOFLAGS="-mod=readonly -p=1",
                GOPATH=str(work / "gopath"), ANDROID_HOME="/work/android-sdk",
                ANDROID_SDK_ROOT="/work/android-sdk",
                ANDROID_NDK_HOME="/work/android-sdk/ndk/27.0.12077973")
            with zipfile.ZipFile(aar) as z:
                native = [name for name in z.namelist() if name.startswith("jni/") and name.endswith(".so")]
                android_abi = "arm64-v8a" if args.abi == "arm64" else "x86_64"
                if native != [f"jni/{android_abi}/libgojni.so"]:
                    raise ValueError("Unexpected additional runtime/ABI")
                (product / "classes.jar").write_bytes(z.read("classes.jar"))
        run("callback-api", ["javap", "-classpath", product / "classes.jar",
                            "org.amnezia.vpn.protocol.xray.libXray.NativeDNSController"])
        api = (args.evidence / "callback-api.log").read_text()
        if "dnsFailed()" not in api or "bindDNS(long, java.lang.String)" not in api:
            raise ValueError("Typed frontend failure callback missing from JNI API")
        if args.runtime_probe:
            run("fault-api", ["javap", "-classpath", product / "classes.jar",
                             "org.amnezia.vpn.protocol.xray.libXray.LibXray"])
            if "probeAbortNativeDNS()" not in (args.evidence / "fault-api.log").read_text():
                raise ValueError("Explicit test-only fault entry missing")
        if not hit:
            atomic_json(record, {"sha256": sha256(aar), "key": key,
                        "scope": "TEST-ONLY tagged fault AAR; NOT production" if args.runtime_probe
                                 else "JNI/API probe; not APK/device acceptance"})
        result = {"aar": str(aar), "sha256": sha256(aar), "cache_hit": hit,
                  "source_bytes_written": bootstrap_bytes + written,
                  "incremental_source_bytes_written": written, "bootstrap_bytes_written": bootstrap_bytes,
                  "tools_copied": 0}
        evidence_json("result.json", result)
        # Public measurements, unlike private workspace ownership records.
        for path in args.evidence.glob("*.json"):
            path.chmod(0o644)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
