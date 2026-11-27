#!/usr/bin/env python3
"""Build current DNS in the existing locked Xray runtime, without toolchain copies."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
if os.name != "nt":
    import resource

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256
from prepare_cached_source import write_changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, default=Path("/cache/conan/p/amnezdf5baa13affd6/s"))
    parser.add_argument("--go", type=Path, default=Path("/cache/conan/p/go38a90af33defe/p/bin/go"))
    parser.add_argument("--platform", choices=("linux", "windows"), default="linux")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cache-root", type=Path, default=Path("/work/lab-cache"))
    parser.add_argument("--go-cache", type=Path, default=Path("/work/go-build-cache"))
    parser.add_argument("--module-cache", type=Path, action="append",
        help="Existing read-only module caches, in selection order; repeat to reuse several")
    args = parser.parse_args()
    if os.name != "nt":
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.platform == "windows" and os.name != "nt":
        parser.error("Windows runtime acceptance requires the native Windows host")
    args.evidence.mkdir(parents=True, exist_ok=False)
    recipe = ROOT / "recipes/amnezia-xray-bindings/native_dns.py"
    spec = importlib.util.spec_from_file_location("desktop_dns_overlay", recipe)
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
               GOTELEMETRY="off", GOMAXPROCS="2",
               GOMEMLIMIT="768MiB" if args.platform == "windows" else "1536MiB",
               GOCACHE=str(args.go_cache),
               CGO_ENABLED="1", GOOS=args.platform, GOARCH="amd64", CC=args.cc)
    cache = Cache(args.cache_root)
    with cache.workspace("desktop-native-dns-xray140-" + args.platform + "-amd64-go127") as work:
        roots = args.module_cache or [
            Path("/cache/conan/p/b/amnez5264b8d8f04b6/b/build/gopath/pkg/mod"),
            Path("/integration/modules"), Path("/cache/go/modules")]
        modules = work / "modules"
        modules.mkdir(exist_ok=True)
        links = 0

        def reference(relative, source):
            nonlocal links
            target = modules / relative
            if target.is_symlink():
                if not target.exists():
                    raise ValueError("Missing referenced module cache retained: " + str(target))
                return
            if target.exists():
                return # Existing Go-cache entries are never replaced or pruned.
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(source.resolve(), target_is_directory=source.is_dir())
            links += 1

        for root in roots:
            if not root.is_dir() or root.resolve().is_relative_to(modules.resolve()):
                raise ValueError("Invalid existing module cache: " + str(root))
            for parent, directories, files in os.walk(root):
                parent = Path(parent)
                if parent == root:
                    directories[:] = [name for name in directories if name != "cache"]
                for name in list(directories):
                    if "@" in name:
                        source = parent / name
                        reference(source.relative_to(root), source)
                        directories.remove(name) # Never walk/copy module source trees.
            download = root / "cache/download"
            if download.is_dir():
                for parent, directories, files in os.walk(download):
                    directories[:] = [name for name in directories if name != "sumdb"]
                    for name in files:
                        if name.endswith((".mod", ".info", ".zip", ".ziphash")):
                            source = Path(parent) / name
                            reference(source.relative_to(root), source)
        env["GOMODCACHE"] = str(modules)
        atomic_json(args.evidence / "storage.json", {"module_cache_links_created": links,
            "module_bytes_copied": 0, "existing_module_caches": list(map(str, roots))})
        (args.evidence / "storage.json").chmod(0o644)
        module = work / "source"
        source_manifest = work / "source-manifest.json"
        previous = json.loads(source_manifest.read_text()) if source_manifest.exists() else {}
        # Stage only the tiny upstream binding and DNS sources, never a module
        # cache, SDK, toolchain or build tree. The stable workspace writes only
        # changed bytes, preserving all unrelated/unowned files.
        with tempfile.TemporaryDirectory(prefix="desktop-dns-source-") as temporary:
            stage = Path(temporary)
            for name in ("main.go", "go.mod", "go.sum", "Makefile", "LICENSE"):
                (stage / name).write_bytes((args.upstream / name).read_bytes())
            overlay.prepare(stage, ROOT / "native/routing/nativedns",
                            ROOT / "native/routing/desktopbridge/native_dns.go")
            desired = {str(p.relative_to(stage)): p.read_bytes() for p in stage.rglob("*") if p.is_file()}
        if set(previous) - set(desired):
            raise ValueError("Removed owned source retained for investigation")
        written, sources = 0, {}
        for name, data in desired.items():
            target = module / name
            digest = hashlib.sha256(data).hexdigest()
            if target.exists() and sha256(target) not in {previous.get(name), digest}:
                raise ValueError("Unowned/externally changed desktop source retained: " + name)
            written += write_changed(target, data)
            sources[name] = digest
        atomic_json(source_manifest, sources)

        def run(name, command, cwd=None, quiet=False):
            result = subprocess.run(list(map(str, command)), cwd=cwd or module, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (args.evidence / (name + ".raw")).write_bytes(result.stdout)
            text = result.stdout.decode("utf-8", errors="replace")
            (args.evidence / (name + ".log")).write_text(text)
            print(name + ": exit " + str(result.returncode) if quiet else text, flush=True)
            if result.returncode:
                raise SystemExit(result.returncode)
            return text

        flags = ["-mod=readonly", "-p=1", "-tags=amnezia_native_dns", "-trimpath",
                 "-ldflags=-w -s -buildid=",
                 "-buildmode=c-shared" if args.platform == "windows" else "-buildmode=c-archive"]
        identity = {"scope": "existing-desktop-xray-runtime-" + args.platform + "-amd64",
            "sources": {name: digest for name, digest in sources.items() if not name.endswith("_test.go")},
            "go": run("go-version", [args.go, "version"]).strip(), "flags": flags,
            "upstream_mod": sha256(args.upstream / "go.mod"), "upstream_sum": sha256(args.upstream / "go.sum")}
        if args.platform == "windows":
            identity["cc_sha256"] = sha256(Path(args.cc))
            identity["cc_version"] = run("cc-version", [args.cc, "--version"]).strip()
        atomic_json(args.evidence / "inputs.json", identity)
        (args.evidence / "inputs.json").chmod(0o644)
        # Compare the ACTUALLY COMPILED graph against the unchanged upstream.
        # `go list -m all` additionally needs unrelated, unused platform/test
        # module metadata (e.g. old Docker/mobile modules); fetching those is
        # neither a dependency guarantee nor necessary for this offline build.
        template = "{{if .Module}}{{.Module.Path}}\t{{.Module.Version}}\t{{with .Module.Replace}}{{.Path}}\t{{.Version}}{{end}}{{end}}"
        graph_command = [args.go, "list", "-mod=readonly", "-tags=amnezia_native_dns", "-deps", "-f", template, "."]

        def graph(text):
            result = {}
            for line in text.splitlines():
                if not line:
                    continue
                fields = line.split("\t")
                fields += [""] * (4 - len(fields))
                if fields[0] != "xray_binding":
                    result[fields[0]] = fields[1:4]
            return result

        before = graph(run("compiled-modules-before", graph_command, args.upstream, quiet=True))
        after = graph(run("compiled-modules-after", graph_command, quiet=True))
        if any(after.get(name) != value for name, value in before.items()) or set(after) - set(before) != {overlay.MODULE}:
            raise ValueError("DNS changed the existing compiled Xray dependency graph")
        atomic_json(args.evidence / "dependency-graph.json",
                    {"compiled_before": before, "compiled_after": after, "only_added_module": overlay.MODULE})
        (args.evidence / "dependency-graph.json").chmod(0o644)
        run("dns-race", [args.go, "test", "-mod=readonly", "-p=1", "-race",
                        "-count=1", "-timeout=60s", "-v", overlay.MODULE])
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        product = cache.root / "products" / key
        binary = product / ("amnezia_xray.dll" if args.platform == "windows" else "amnezia_xray.a")
        header = product / "amnezia_xray.h"
        import_library = product / "amnezia_xray.lib"
        receipt, pending = product / "artifact.json", product / "build-input.json"
        hit = receipt.exists()
        if hit:
            saved = json.loads(receipt.read_text())
            if sha256(binary) != saved["archive_sha256"] or sha256(header) != saved["header_sha256"]:
                raise ValueError("Immutable desktop native product changed")
            if args.platform == "windows" and sha256(import_library) != saved["import_library_sha256"]:
                raise ValueError("Immutable native import library changed")
        else:
            if product.exists():
                if not pending.exists() or json.loads(pending.read_text()) != identity:
                    raise ValueError("Unowned partial desktop product retained")
            else:
                product.mkdir(parents=True)
                atomic_json(pending, identity)
            run("archive-build", [args.go, "build", *flags, "-o", binary])
            extra = {}
            if args.platform == "windows":
                tools = Path(args.cc).parent
                run("import-definition", [tools / "gendef.exe", binary.name], cwd=product)
                run("import-library", [tools / "dlltool.exe", "-d", "amnezia_xray.def",
                    "-l", import_library, "-D", binary.name], cwd=product)
                extra["import_library_sha256"] = sha256(import_library)
            atomic_json(receipt, {"archive_sha256": sha256(binary), "header_sha256": sha256(header),
                **extra, "identity": identity,
                "scope": "current existing-runtime native library; NOT platform/VPN acceptance"})
        result = {"archive": str(binary), "archive_sha256": sha256(binary),
            "header_sha256": sha256(header), "cache_hit": hit, "source_bytes_written": written,
            "temporary_overlay_bytes": sum(len(data) for data in desired.values()),
            "scope": "current existing locked runtime; NOT platform/VPN acceptance"}
        atomic_json(args.evidence / "result.json", result)
        (args.evidence / "result.json").chmod(0o644)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
