#!/usr/bin/env python3
"""Build the production recipe overlay in a stable symlink-source workspace."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256
from prepare_cached_source import write_changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, default=Path("/cache/conan/p/openva87ad8a6ff2f5/s/src"))
    parser.add_argument("--abi", choices=("arm64-v8a", "armeabi-v7a", "x86", "x86_64"), default="arm64-v8a")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
               GOTELEMETRY="off", GOMAXPROCS="2", GOMEMLIMIT="1536MiB",
               GOCACHE="/work/go-build-cache", GOMODCACHE="/integration/modules",
               SWIG_LIB="/cache/conan/p/swig5f85cc16f16cd/p/bin/swiglib",
               PATH="/cache/conan/p/go38a90af33defe/p/bin:" + os.environ["PATH"])
    os.environ.update(env)
    cache = Cache("/work/lab-cache")
    profile = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "x86": "386", "x86_64": "amd64"}[args.abi]
    with cache.workspace("android-openvpn-production-recipe-ndk27-" + profile) as work:
        source, build, support = (work / name for name in ("source", "build", "support"))
        for path in (source, build, support):
            path.mkdir(exist_ok=True)

        def link(target, original):
            if target.is_symlink():
                if target.resolve() != original.resolve():
                    raise ValueError("Source symlink identity changed: " + str(target))
            elif target.exists():
                raise ValueError("Unowned source retained: " + str(target))
            else:
                target.symlink_to(original.resolve(), target_is_directory=original.is_dir())

        for path in args.upstream.iterdir():
            if path.name != "CMakeLists.txt":
                link(source / path.name, path)
        # The isolated original-Cloak source is architecture-independent. Reuse
        # it read-only across ABI build directories instead of duplicating its
        # dependency closure per ABI.
        if profile != "arm64":
            link(build / "native-dns-cloak",
                 cache.root / "workspaces/android-openvpn-production-recipe-ndk27-arm64/build/native-dns-cloak")
        # Only the 5-KiB top-level recipe input is mutable, never a native source
        # tree/SDK/build-tree copy. Upstream submodules stay read-only.
        if not (source / "CMakeLists.txt").exists():
            write_changed(source / "CMakeLists.txt", (args.upstream / "CMakeLists.txt").read_bytes())
        recipe = ROOT / "recipes/openvpn-pt-android"
        for path in recipe.iterdir():
            if path.name.startswith("native_dns") or path.name == "prepare_cloak_dns.py":
                link(support / path.name, path)
        link(support / "routing", ROOT / "native/routing")
        spec = importlib.util.spec_from_file_location("openvpn_recipe", recipe / "conanfile.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        recipe_digest = sha256(recipe / "conanfile.py")
        module.OpenvpnPtAndroid._prepare_dns(SimpleNamespace(
            source_folder=str(source), build_folder=str(build), export_sources_folder=str(support)))
        native_inputs = {str(p.relative_to(build / "native-dns-include")): sha256(p)
                         for p in (build / "native-dns-include").rglob("*") if p.is_file()}
        native_cmake = sha256(source / "CMakeLists.txt")
        cloak_inputs = sha256(build / "native-dns-cloak/.native-dns-sources.json")

        def run(name, command, quiet=False):
            result = subprocess.run(list(map(str, command)), env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (args.evidence / (name + ".raw")).write_bytes(result.stdout)
            text = result.stdout.decode("utf-8", errors="replace")
            (args.evidence / (name + ".log")).write_text(text)
            print((name + ": exit " + str(result.returncode)) if quiet else text, flush=True)
            if result.returncode:
                raise SystemExit(result.returncode)
            return text

        ndk = Path("/work/android-sdk/ndk/27.0.12077973")
        run("configure", ["cmake", "-S", source, "-B", build, "-G", "Ninja",
                         "-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
                         "-DANDROID_ABI=" + args.abi, "-DANDROID_PLATFORM=android-24",
                         "-DCMAKE_BUILD_TYPE=Release",
                         "-DAMNEZIA_DNS_CLOAK_SOURCE=" + str(build / "native-dns-cloak"),
                         "-DSWIG_EXECUTABLE=/cache/conan/p/swig5f85cc16f16cd/p/bin/swig"])
        run("build", ["cmake", "--build", build, "--parallel", "2", "--target",
                      "ck_ovpn_plugin_go", "ovpn3", "ovpnutil", "rsapss"])
        dependencies = run("native-include-dependencies", [
            "ninja", "-C", build, "-t", "deps", "CMakeFiles/ovpn3.dir/openvpn3/client/ovpncli.cpp.o"],
            quiet=True)
        for header in ("openvpn/tun/builder/base.hpp", "openvpn/tun/builder/client.hpp",
                       "openvpn/tun/client/tunprop.hpp", "openvpn/client/async_resolve/asio.hpp",
                       "native_dns_owner.hpp", "native_dns_engine.hpp", "native_dns_options.hpp",
                       "native_dns_bootstrap.hpp", "native_dns.h"):
            if str(build / "native-dns-include" / header) not in dependencies:
                raise RuntimeError("Production TU did not consume its owned overlay: " + header)
        products = {p.name: sha256(p) for p in build.glob("*.so")}
        java = {str(p.relative_to(build / "ovpn3")): sha256(p)
                for p in (build / "ovpn3").glob("*.java")}
        if not java or "libovpn3.so" not in products or "libck-ovpn-plugin.so" not in products:
            raise RuntimeError("Production JNI and same-build Java products missing")
        record = {"workspace": str(work), "abi": args.abi, "libraries": products, "java": java,
                  "recipe_sha256": recipe_digest, "native_inputs": native_inputs,
                  "native_cmake_sha256": native_cmake, "cloak_manifest_sha256": cloak_inputs,
                  "scope": "production native build and generated Java; NOT Android device/VPN acceptance"}
        # Package identity is its ACTUAL contents, not the run/workspace or a
        # recipe-only edit. Keep build-input provenance in this run's evidence;
        # identical packaged bytes may reuse the same immutable product.
        package_inputs = {"libraries": products, "java": java,
            "header": sha256(build / "libck-ovpn-plugin.h"),
            "native_dns_header": sha256(support / "native_dns.h"),
            "notices": {str(p.relative_to(build / "native-dns-cloak")): sha256(p)
                for p in (build / "native-dns-cloak/native-dns-notices").rglob("*") if p.is_file()},
            "provenance": sha256(build / "native-dns-cloak/cmd/ck-ovpn-plugin/native-cloak-provenance.json"),
            "original_cloak": {name: sha256(build / "native-dns-cloak" / name)
                for name in ("native-original-cloak.mod", "native-original-cloak.sum")}}
        key = hashlib.sha256(json.dumps(package_inputs, sort_keys=True).encode()).hexdigest()
        package = cache.root / "products" / key / "openvpn-pt-android"
        receipt = package.parent / "artifact.json"
        package_hit = receipt.exists()
        if package_hit:
            saved = json.loads(receipt.read_text())
            if any(not (package / name).is_file() or sha256(package / name) != digest
                   for name, digest in saved["files"].items()):
                raise ValueError("Immutable production package changed")
        else:
            from conan.api.output import ConanOutput
            module.OpenvpnPtAndroid.package(SimpleNamespace(
                build_folder=str(build), package_folder=str(package),
                export_sources_folder=str(support), output=ConanOutput()))
            files = {str(p.relative_to(package)): sha256(p)
                     for p in package.rglob("*") if p.is_file()}
            atomic_json(receipt, {"files": files, "package_inputs": package_inputs})
        record["package"] = str(package)
        record["package_cache_hit"] = package_hit
        readelf = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
        symbols = run("jni-symbols", [readelf, "--dyn-syms", "--wide", package / "lib/libovpn3.so"], quiet=True)
        for symbol in ("amnezia_1dns_1prepare_1scoped", "tun_1builder_1dns_1bind",
                       "amnezia_1dns_1prepare_1selected", "amnezia_1dns_1prepare_1tunnel",
                       "tun_1builder_1dns_1transport", "tun_1builder_1dns_1tunnel_1allowed"):
            if symbol not in symbols:
                raise RuntimeError("Actual production JNI symbol missing: " + symbol)
        cloak_symbols = run("cloak-dns-symbols", [
            readelf, "--dyn-syms", "--wide", package / "lib/libck-ovpn-plugin.so"], quiet=True)
        exported = {line.split()[-1] for line in cloak_symbols.splitlines() if line.split()}
        for symbol in ("AmneziaOpenVPNDNSStartTunnel", "AmneziaOpenVPNDNSFeedTunnel",
                       "AmneziaOpenVPNDNSStartSelected", "AmneziaOpenVPNDNSStop",
                       "AmneziaOpenVPNDNSQuiesce", "AmneziaOpenVPNDNSResume"):
            if symbol not in exported:
                raise RuntimeError("Actual existing-runtime C ABI symbol missing: " + symbol)
        dynamic = run("jni-needed", [readelf, "--dynamic", package / "lib/libovpn3.so"])
        if "libck-ovpn-plugin.so" not in dynamic:
            raise RuntimeError("Production JNI is not linked to its original Cloak runtime")
        atomic_json(args.evidence / "result.json", record)
        (args.evidence / "result.json").chmod(0o644)
        print(json.dumps({name: record[name] for name in (
            "workspace", "abi", "libraries", "package", "package_cache_hit", "scope")}), flush=True)


if __name__ == "__main__":
    main()
