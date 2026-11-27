"""Add DNS-only native endpoints to the already-linked service Go runtime."""
from pathlib import Path
import re
import shutil

MODULE = "github.com/StannisMod/amnezia-client/native/routing/nativedns"
REQUIRE = f"require {MODULE} v0.0.0\nreplace {MODULE} => ./amnezia-native-dns\n"
MAKE_SOURCE = "SOURCES := main.go"
MAKE_REPLACEMENT = ("SOURCES := $(wildcard *.go) go.mod go.sum "
                    "$(wildcard amnezia-native-dns/*.go) "
                    "amnezia-native-dns/go.mod amnezia-native-dns/go.sum")


def prepare(source, dns_core, bridge):
    source, dns_core = Path(source), Path(dns_core)
    module = source / "go.mod"
    text = module.read_text()
    if not text.startswith("module xray_binding\n"):
        raise RuntimeError("Unexpected native desktop Xray module")
    # Adding the DNS module must not upgrade Xray's existing shared dependencies
    # (particularly its unrelated native TCP implementation).
    for name, version in re.findall(r"^\s*(\S+) (v\S+)", (dns_core / "go.mod").read_text(), re.M):
        if not re.search(r"^\s*" + re.escape(name) + r"\s+" + re.escape(version) + r"(?:\s|$)", text, re.M):
            raise RuntimeError("Native DNS would change an existing Xray dependency: " + name)
    if MODULE in text:
        if text.count(REQUIRE) != 1:
            raise RuntimeError("Inconsistent native DNS module overlay")
    else:
        text += "\n" + REQUIRE
    makefile = source / "Makefile"
    build = makefile.read_text()
    if MAKE_REPLACEMENT not in build:
        if build.count(MAKE_SOURCE) != 1:
            raise RuntimeError("Unexpected native Xray make dependency entry")
        build = build.replace(MAKE_SOURCE, MAKE_REPLACEMENT)
    shutil.copytree(dns_core, source / "amnezia-native-dns", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(bridge, source / "amnezia_native_dns.go")
    module.write_text(text)
    makefile.write_text(build)
