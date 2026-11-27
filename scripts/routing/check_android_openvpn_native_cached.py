#!/usr/bin/env python3
"""Offline cached probe of DNS inside the existing frozen Cloak Go runtime."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256, sync_tree
from prepare_cached_source import write_changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--abi", choices=("host", "arm64", "arm", "386", "amd64"), default="host")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--owner-test", action="store_true")
    parser.add_argument("--api-check", action="store_true")
    parser.add_argument("--swig", type=Path, default=Path("/cache/conan/p/swig5f85cc16f16cd/p/bin/swig"))
    parser.add_argument("--go-root", type=Path, default=Path("/cache/conan/p/go38a90af33defe/p"))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.evidence.mkdir(parents=True, exist_ok=False)
    support = ROOT / "recipes/openvpn-pt-android"
    spec = importlib.util.spec_from_file_location("prepare_cloak_dns", support / "prepare_cloak_dns.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    cache = Cache("/work/lab-cache")
    env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
               GOTELEMETRY="off", GOMAXPROCS="2", GOMEMLIMIT="1536MiB",
               GOCACHE="/work/go-build-cache", GOMODCACHE="/integration/modules")
    go = str(args.go_root / "bin/go")
    with cache.workspace("android-openvpn-native-dns-go127-ndk27") as work:
        module = work / "cloak"
        storage = overlay.prepare(args.upstream, module, ROOT / "native/routing", support, go, env)
        atomic_json(args.evidence / "storage.json", storage)
        (args.evidence / "storage.json").chmod(0o644)
        provenance = module / "cmd/ck-ovpn-plugin/native-cloak-provenance.json"
        (args.evidence / "source-provenance.json").write_bytes(provenance.read_bytes())
        print(json.dumps(storage), flush=True)
        if args.prepare_only:
            return

        def run(name, command, extra=None):
            result = subprocess.run(list(map(str, command)), cwd=module,
                                    env=dict(env, **(extra or {})),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (args.evidence / (name + ".raw")).write_bytes(result.stdout)
            text = result.stdout.decode("utf-8", errors="replace")
            (args.evidence / (name + ".log")).write_text(text)
            print(text, flush=True)
            if result.returncode:
                raise SystemExit(result.returncode)
            return text

        # The DNS half must expose the same real locked TCP identity as the
        # existing backend, not merely a relabeled source folder.
        run("pinned-source", [sys.executable, ROOT / "native/routing/internal/builddeps/verify.py",
                             "--module", module, "--scope", "desktop_android", "--go", go])
        flags = ["-mod=readonly", "-p=1", "-tags=amnezia_openvpn_dns", "-trimpath",
                 "-ldflags=-w -s -buildid= -checklinkname=0", "-buildmode=c-shared"]
        if args.owner_test:
            run("host-race", [go, "test", "-mod=readonly", "-p=1", "-race", "-count=1",
                             "-timeout=60s", "-tags=amnezia_openvpn_dns", "-v", "./cmd/ck-ovpn-plugin"],
                {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1", "CC": "gcc"})
        identity = {"sources": {name: value for name, value in
                    json.loads((module / ".native-dns-sources.json").read_text()).items()
                    if not name.endswith("_test.go")},
                    "abi": args.abi, "flags": flags, "go": run("go-version", [go, "version"]).strip(),
                    "ndk": "27.0.12077973"}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        product = cache.root / "products" / key
        binary, record = product / "libck-ovpn-native-dns-probe.so", product / "artifact.json"
        hit = record.exists()
        if hit:
            if sha256(binary) != json.loads(record.read_text())["sha256"]:
                raise ValueError("Cached native OpenVPN product changed")
        else:
            product.mkdir(parents=True, exist_ok=False)
            extra = {"CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": "amd64", "CC": "gcc"}
            if args.abi != "host":
                compiler = {"arm64": "aarch64", "arm": "armv7a", "386": "i686", "amd64": "x86_64"}[args.abi]
                target_os = "androideabi" if args.abi == "arm" else "android"
                extra.update(GOOS="android", GOARCH=args.abi,
                             CC=f"/work/android-sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/{compiler}-linux-{target_os}24-clang")
                if args.abi == "arm":
                    extra["GOARM"] = "7"
            run("native-build", [go, "build", *flags, "-o", binary, "./cmd/ck-ovpn-plugin"], extra)
            run("binary-pins", [sys.executable, ROOT / "native/routing/internal/builddeps/verify.py",
                                "--module", module, "--binary", binary,
                                "--scope", "desktop_android", "--go", go])
            atomic_json(record, {"sha256": sha256(binary), "identity": identity,
                                 "scope": "native ABI probe; NOT OpenVPN3/device acceptance"})
        result = {"binary": str(binary), "sha256": sha256(binary), "cache_hit": hit, **storage}
        if args.owner_test or args.api_check:
            if args.owner_test and args.abi != "host":
                raise ValueError("Owner execution requires the explicitly named host probe")
            native = args.upstream.parent / "openvpn3"
            spec = importlib.util.spec_from_file_location("openvpn_native_dns", support / "native_dns.py")
            headers = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(headers)
            desired = headers.prepare(native, support)
            include = work / "native-includes"
            owned_headers = work / "native-includes.json"
            previous = json.loads(owned_headers.read_text()) if owned_headers.exists() else {}
            for name in desired:
                target = include / name
                if target.exists() and sha256(target) not in (previous.get(name), hashlib.sha256(desired[name]).hexdigest()):
                    raise ValueError("Unowned OpenVPN include override retained: " + name)
            written = sum(write_changed(include / name, data) for name, data in desired.items())
            manifest = {name: hashlib.sha256(data).hexdigest() for name, data in desired.items()}
            atomic_json(owned_headers, manifest)
            atomic_json(args.evidence / "native-headers.json", {
                "sha256": manifest, "source_bytes_written": written,
                "scope": "checked original OpenVPN3 headers + native host owner fixture"})
            (args.evidence / "native-headers.json").chmod(0o644)
            if args.owner_test:
                executable = Path("/tmp/amnezia-openvpn-native-owner-test")
                run("owner-compile", ["g++", "-std=c++17", "-pthread", "-g", "-O1",
                                     "-DUSE_ASIO", "-DASIO_STANDALONE",
                                     "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                                     "-I" + str(include), "-I" + str(native),
                                     "-I" + str(args.upstream.parent / "asio/asio/include"),
                                     ROOT / "scripts/routing/android-openvpn-dns/native_owner_test.cpp",
                                     str(binary), "-Wl,-rpath," + str(product), "-o", executable])
                fixture_source = ROOT / "scripts/routing/android-openvpn-dns/tls_upstream.go"
                fixture_key = hashlib.sha256(json.dumps({
                    "source": sha256(fixture_source), "go": identity["go"], "scope": "test-only-native-dns-tls"
                }, sort_keys=True).encode()).hexdigest()
                fixture_product = cache.root / "products" / fixture_key
                fixture = fixture_product / "tls-upstream"
                fixture_record = fixture_product / "artifact.json"
                if fixture_record.exists():
                    if sha256(fixture) != json.loads(fixture_record.read_text())["sha256"]:
                        raise ValueError("Immutable TLS test fixture changed")
                else:
                    fixture_product.mkdir(parents=True, exist_ok=False)
                    run("tls-fixture-build", [go, "build", "-mod=readonly", "-p=1", "-trimpath",
                        "-ldflags=-s -w -buildid=", "-o", fixture, fixture_source],
                        {"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})
                    atomic_json(fixture_record, {"sha256": sha256(fixture),
                                                "scope": "test-only TLS upstream, never a production payload"})
                with tempfile.TemporaryDirectory(prefix="native-dns-test-ca-") as trust:
                    ca = Path(trust) / "ca.pem"
                    fixture_process = subprocess.Popen([str(fixture), str(ca)], env=env,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    first = fixture_process.stdout.readline()
                    try:
                        selected = json.loads(first)
                        if selected["ca"] != str(ca) or not ca.is_file():
                            raise ValueError("TLS fixture trust publication differs")
                        (args.evidence / "tls-fixture-ca.pem").write_bytes(ca.read_bytes())
                        atomic_json(args.evidence / "tls-fixture.json", {
                            "source_sha256": sha256(fixture_source), "binary_sha256": sha256(fixture),
                            "test_ca_sha256": sha256(ca),
                            "scope": "process-local test CA through normal system trust loader; no TLS bypass"})
                        (args.evidence / "tls-fixture.json").chmod(0o644)
                        run("owner-execute", [executable], {
                            "SSL_CERT_FILE": str(ca), "SSL_CERT_DIR": trust,
                            "AMNEZIA_TEST_DOT": selected["dot"], "AMNEZIA_TEST_DOH": selected["doh"],
                            "AMNEZIA_TEST_DOH_URL": selected["url"]})
                    finally:
                        # EOF requests graceful listener/connection join. Never
                        # terminate/kill a fixture with pending native cleanup.
                        fixture_process.stdin.close()
                        fixture_process.stdin = None
                        stdout, stderr = fixture_process.communicate()
                        output = first + stdout + stderr
                        (args.evidence / "tls-fixture.raw").write_bytes(output)
                        (args.evidence / "tls-fixture.log").write_text(output.decode("utf-8", errors="replace"))
                        if fixture_process.returncode:
                            raise RuntimeError("TLS upstream fixture did not retire normally")
                result["owner_test"] = "passed (host C++ ASan/UBSan + real libck C ABI; not Android/TUN)"
            if args.api_check:
                api = work / "swig-api"
                identity = {**manifest, "swig": sha256(args.swig)}
                marker = work / "swig-api.json"
                hit = marker.exists() and json.loads(marker.read_text()) == identity
                if marker.exists():
                    prior_sources = json.loads((api / ".lab-sources.json").read_text())
                    for name, value in prior_sources.items():
                        if sha256(api / name) != value["sha256"]:
                            raise ValueError("Modified generated API source retained: " + name)
                if not hit:
                    # Generate in RAM, then write only changed bytes to the
                    # existing API workspace. No SDK/toolchain/source-tree copy.
                    with tempfile.TemporaryDirectory(prefix="ovpn-swig-") as scratch:
                        scratch = Path(scratch)
                        java = scratch / "java"
                        java.mkdir()
                        run("swig", [args.swig, "-c++", "-java", "-package", "net.openvpn.ovpn3",
                                     "-DOPENVPN_PLATFORM_ANDROID", "-I" + str(include),
                                     "-I" + str(native / "client"), "-I" + str(native),
                                     "-outdir", java, "-o", scratch / "ovpncli_wrap.cxx",
                                     include / "client/ovpncli.i"],
                            {"SWIG_LIB": str(args.swig.parent / "swiglib")})
                        source_stats = sync_tree(scratch, api)
                        atomic_json(marker, identity)
                        result["api_source_bytes_written"] = source_stats["bytes_written"]
                else:
                    result["api_source_bytes_written"] = 0
                header = api / "libck-ovpn-plugin.h"
                target = binary.with_suffix(".h")
                if header.is_symlink():
                    if header.resolve() != target:
                        header.unlink()  # Owned generated-header pointer, never source/artifact bytes.
                        header.symlink_to(target)
                elif header.exists():
                    raise ValueError("Unowned generated Cloak header retained")
                else:
                    header.symlink_to(target)
                root = native.parent
                abi = "arm64" if args.abi == "host" else args.abi
                compiler = {"arm64": "aarch64", "arm": "armv7a", "386": "i686", "amd64": "x86_64"}[abi]
                clang = f"/work/android-sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/{compiler}-linux-android24-clang++"
                flags = ["-std=c++17", "-fsyntax-only", "-DUSE_OPENSSL",
                         "-DHAVE_CONFIG_H", "-DHAVE_LZO", "-DHAVE_LZ4", "-DASIO_STANDALONE",
                         "-DUSE_ASIO", "-DENABLE_EXTERNAL_PKI", "-DOPENSSL_API_COMPAT=0x10200000L",
                         '-DGIT_VERSION_STRING="native-dns-probe"', "-DOPENVPN_SHOW_SESSION_TOKEN",
                         "-DOPENVPN_ALLOW_INSECURE_CERTPROFILE"]
                for path in (include, api, native, native / "client", root / "lzo/include",
                             root / "openssl/include", root / "openvpn-config",
                             root / "asio/asio/include", root / "lz4/lib"):
                    flags.append("-I" + str(path))
                run("android-client-syntax", [clang, *flags, native / "client/ovpncli.cpp"])
                run("android-director-syntax", [clang, *flags, api / "ovpncli_wrap.cxx"])
                with tempfile.TemporaryDirectory(prefix="ovpn-classes-") as classes_path:
                    classes = Path(classes_path)
                    run("java-api", ["javac", "-d", classes, *sorted((api / "java").glob("*.java"))])
                    text = run("java-signatures", ["javap", "-classpath", classes,
                                                   "net.openvpn.ovpn3.ClientAPI_TunBuilderBase"])
                    for method in ("amnezia_dns_policy(boolean)", "amnezia_dns_release_policy()",
                                   "amnezia_dns_owned()", "tun_builder_dns_dispatch(long, long, int, java.lang.String, int)",
                                   "tun_builder_dns_cancel(long, long)", "tun_builder_dns_failed(long)",
                                   "tun_builder_dns_retired(long)", "tun_builder_dns_bind(long, int)",
                                   "amnezia_dns_prepare_scoped(java.lang.String, java.lang.String)"):
                        if method not in text:
                            raise ValueError("Missing measured native callback API: " + method)
                    contents = {str(path.relative_to(classes)): path.read_bytes()
                                for path in sorted(classes.rglob("*.class"))}
                    classes_key = hashlib.sha256(json.dumps({
                        name: hashlib.sha256(data).hexdigest() for name, data in contents.items()
                    }, sort_keys=True).encode()).hexdigest()
                    jar_product = cache.root / "products" / classes_key
                    jar, jar_record = jar_product / "native-openvpn-api-fixture.jar", jar_product / "artifact.json"
                    if jar_record.exists():
                        if sha256(jar) != json.loads(jar_record.read_text())["sha256"]:
                            raise ValueError("Cached native API fixture changed")
                    else:
                        jar_product.mkdir(parents=True, exist_ok=False)
                        with zipfile.ZipFile(jar, "w") as archive:
                            for name, data in contents.items():
                                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                                archive.writestr(info, data)
                        atomic_json(jar_record, {"sha256": sha256(jar), "classes_key": classes_key,
                                    "scope": "compile-only SWIG API fixture, not production JNI payload"})
                result["api_jar"] = str(jar)
                result["api_jar_sha256"] = sha256(jar)
                result["api_scope"] = "SWIG API + real Android compiler syntax only; not JNI/runtime invocation"
        atomic_json(args.evidence / "result.json", result)
        (args.evidence / "result.json").chmod(0o644)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
