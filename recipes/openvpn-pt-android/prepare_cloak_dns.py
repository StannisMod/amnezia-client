"""Prepare DNS inside the EXISTING Cloak runtime without upgrading Cloak code.

The original Cloak dependency closure is source-isolated under an internal
namespace. The DNS half uses the existing locked routing graph. No new shared
library/runtime, dependency-version substitution or full-flow adapter is added.
All transformed sources retain original byte hashes and module/license identity.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


CLOAK = "github.com/cbeuw/Cloak"
NAMESPACE = CLOAK + "/internal/amneziacloakdeps/"
ROUTING = "github.com/StannisMod/amnezia-client/native/routing"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_stream(text):
    decoder, position = json.JSONDecoder(), 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            return
        row, position = decoder.raw_decode(text, position)
        yield row


def isolate_imports(data, modules):
    """Rewrite import/linkname identities only, never crypto/protocol logic."""
    text = data.decode("utf-8")
    if NAMESPACE in text:
        raise ValueError("Cloak source is already namespaced")

    def path(value, symbol=False):
        for module in sorted(modules, key=len, reverse=True):
            if value == module or value.startswith(module + "/") or (symbol and value.startswith(module + ".")):
                return NAMESPACE + value
        return value

    # Import declarations have no escape sequences in the pinned Go sources.
    in_import = False
    output = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if re.match(r"^import\s*\(", stripped):
            in_import = True
        elif in_import and stripped == ")":
            in_import = False
        if in_import or re.match(r"^import\s+", stripped):
            line = re.sub(r'"([^"\n]+)"', lambda m: '"' + path(m[1]) + '"', line)
        if stripped.startswith("//go:linkname "):
            line = re.sub(r"(?m)^(//go:linkname\s+\S+\s+)(\S+)",
                          lambda m: m[1] + path(m[2], symbol=True), line)
        output.append(line)
    return "".join(output).encode()


def prepare(upstream, target, routing, support, go="go", environment=None):
    upstream, target, routing, support = map(Path, (upstream, target, routing, support))
    env = dict(os.environ)
    env.update(environment or {})
    env.update(GOTOOLCHAIN="local", GOTELEMETRY="off")
    packages, modules = {}, {}
    frozen = {name: (upstream / name).read_bytes() for name in ("go.mod", "go.sum")}
    if not frozen["go.mod"].startswith(("module " + CLOAK + "\n").encode()):
        raise ValueError("Unexpected Cloak module")
    # Discover every supported Android architecture, not merely the host's
    # active .go files. This never builds/downloads a separate toolchain.
    for goos, arch in (("linux", "amd64"), ("android", "arm64"), ("android", "arm"),
                       ("android", "amd64"), ("android", "386")):
        result = subprocess.run([go, "list", "-mod=readonly", "-deps", "-json",
                                 "./cmd/ck-ovpn-plugin"], cwd=upstream,
                                env=dict(env, GOOS=goos, GOARCH=arch, CGO_ENABLED="1"),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
        for package in json_stream(result.stdout.decode()):
            if package.get("Standard"):
                continue
            module = package.get("Module", {})
            if not module.get("Path") or module.get("Replace"):
                raise ValueError("Unpinned/replaced Cloak dependency")
            previous = packages.get(package["ImportPath"], {})
            package["EmbedFiles"] = sorted(set(package.get("EmbedFiles", []))
                                            | set(previous.get("EmbedFiles", [])))
            packages[package["ImportPath"]] = package
            if module["Path"] != CLOAK:
                modules[module["Path"]] = module
    if any((upstream / name).read_bytes() != content for name, content in frozen.items()):
        raise ValueError("Original Cloak graph changed during discovery")
    desired, origins = {}, {}

    def add(name, data, original=None):
        if name in desired and desired[name] != data:
            raise ValueError("Conflicting native DNS source: " + name)
        desired[name] = data
        if original is not None:
            origins[name] = digest(original)

    for name, package in sorted(packages.items()):
        source = Path(package["Dir"])
        relative = (name.removeprefix(CLOAK + "/") if package["Module"]["Path"] == CLOAK
                    else "internal/amneziacloakdeps/" + name)
        files = set(p for p in source.iterdir() if p.is_file()
                    and p.suffix in {".go", ".s", ".S", ".h", ".c", ".cc", ".cpp"}
                    and not p.name.endswith("_test.go"))
        for embedded in package.get("EmbedFiles", []):
            files.add(source / embedded)
        for path in sorted(files):
            original = path.read_bytes()
            data = isolate_imports(original, modules) if path.suffix == ".go" else original
            if str(Path(relative) / path.relative_to(source)) == "cmd/ck-ovpn-plugin/ck-ovpn-plugin.go":
                if digest(original) != "583a2a89b6b645d36a8e2666377587d0a6ba16cd1d2f3f9771f96cac2e7d1e6c":
                    raise ValueError("Unexpected original Cloak socket/bootstrap owner")
                text = data.decode()
                needle = "func socket_get_fd(network string, address string, c syscall.RawConn) error {"
                if text.count(needle) != 1 or text.count("singleplexTCPConfig = *rawConfig") != 1:
                    raise ValueError("Original Cloak policy hooks changed")
                text = text.replace(needle, needle + """
	if err := amneziaCloakSocketPolicy(network, address); err != nil { return err }
""", 1)
                text = text.replace("singleplexTCPConfig = *rawConfig", """
	if err := amneziaCloakEndpointPolicy(rawConfig.RemoteHost); err != nil {
		log.Error(err)
		return -1
	}
	singleplexTCPConfig = *rawConfig""", 1)
                dialer = "d := &net.Dialer{Control: socket_get_fd, KeepAlive: remoteConfig.KeepAlive}"
                if text.count(dialer) != 1:
                    raise ValueError("Original Cloak scoped dialer changed")
                text = text.replace(dialer,
                    "d := &amneziaCloakDialer{Dialer: net.Dialer{Control: socket_get_fd, KeepAlive: remoteConfig.KeepAlive}}", 1)
                data = text.encode()
            add(str(Path(relative) / path.relative_to(source)), data, original)
    licenses = {}
    license_modules = dict(modules)
    license_modules[CLOAK] = {"Dir": str(upstream)}
    for name, module in sorted(license_modules.items()):
        root = Path(module["Dir"])
        found = [p for p in root.iterdir() if p.is_file()
                 and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))]
        if not found:
            raise ValueError("Missing original Cloak dependency license: " + name)
        for path in sorted(found):
            key = "native-dns-notices/" + name + "/" + path.name
            add(key, path.read_bytes(), path.read_bytes())
            licenses[key] = digest(path.read_bytes())
    for name in ("native_dns_cloak.go", "native_dns_cloak_test.go", "native_dns.h"):
        add("cmd/ck-ovpn-plugin/" + name, (support / name).read_bytes())
    # Keep the original module/sum intact as source evidence. The combined build
    # graph selects pinned DNS dependencies, while ALL original Cloak packages
    # still compile their original dependency source versions in private scope.
    native_mod = (routing / "go.mod").read_text()
    native_mod = native_mod.replace("module " + ROUTING + "\n", "module " + CLOAK + "\n", 1)
    native_mod = native_mod.replace("=> ./nativedns", "=> ./amnezia-routing/nativedns")
    native_mod += "\nrequire " + ROUTING + " v0.0.0\nreplace " + ROUTING + " => ./amnezia-routing\n"
    add("go.mod", native_mod.encode())
    add("go.sum", (routing / "go.sum").read_bytes())
    add("native-original-cloak.mod", frozen["go.mod"])
    add("native-original-cloak.sum", frozen["go.sum"])
    provenance = {
        "scope": "existing libck-ovpn-plugin runtime; isolated original Cloak code + pinned DNS",
        "original_cloak_graph": {name: digest(data) for name, data in frozen.items()},
        "routing_graph": {name: digest((routing / name).read_bytes()) for name in ("go.mod", "go.sum")},
        "routing_sources": {str(path.relative_to(routing)): digest(path.read_bytes())
                            for directory in ("dnsguard", "internal/builddeps", "nativedns")
                            for path in sorted((routing / directory).iterdir())
                            if path.is_file() and (path.suffix in {".go", ".json", ".mod", ".sum"})
                            and not path.name.endswith("_test.go")},
        "original_modules": {name: {key: value.get(key) for key in ("Version", "Sum", "GoModSum")}
                             for name, value in sorted(modules.items())},
        "original_source_sha256": origins, "licenses": licenses,
        "adapter_sha256": {name: digest((support / name).read_bytes())
                           for name in ("native_dns_cloak.go", "native_dns.h")},
        "adapted_entry_sha256": digest(desired["cmd/ck-ovpn-plugin/ck-ovpn-plugin.go"]),
    }
    add("cmd/ck-ovpn-plugin/native-cloak-provenance.json",
        (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode())
    add("cmd/ck-ovpn-plugin/native_cloak_provenance.go", b'''package main
import _ "embed"
//go:embed native-cloak-provenance.json
var openvpnDNSProvenance string
''')
    target.mkdir(parents=True, exist_ok=True)
    ownership = target / ".native-dns-sources.json"
    prior = json.loads(ownership.read_text()) if ownership.exists() else {}
    if not ownership.exists() and any(target.iterdir()):
        raise ValueError("Unmanifested Cloak DNS workspace retained")
    for name, sha in prior.items():
        path = target / name
        if not path.is_file() or digest(path.read_bytes()) != sha:
            raise ValueError("Externally modified Cloak DNS source retained: " + name)
    for name in desired:
        path = target / name
        if path.exists() and name not in prior:
            raise ValueError("Unowned Cloak DNS source retained: " + name)
    link = target / "amnezia-routing"
    if link.is_symlink():
        if link.resolve() != routing.resolve():
            raise ValueError("Native DNS routing source changed")
    elif link.exists():
        raise ValueError("Unowned routing source retained")
    written = 0
    for name, data in desired.items():
        path = target / name
        if path.exists() and path.read_bytes() == data:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        written += len(data)
    for name in prior.keys() - desired.keys():
        (target / name).unlink() # Only previously verified owned sources.
    if not link.exists():
        link.symlink_to(routing.resolve(), target_is_directory=True)
    current = {name: digest(data) for name, data in desired.items()}
    # This manifest is a cache ownership record, not an acceptance result.
    temporary = ownership.with_suffix(".next")
    temporary.write_text(json.dumps(current, sort_keys=True))
    temporary.replace(ownership)
    return {"source_bytes_written": written, "source_files": len(current),
            "original_cloak_modules": provenance["original_modules"],
            "provenance_sha256": digest(desired["cmd/ck-ovpn-plugin/native-cloak-provenance.json"])}
