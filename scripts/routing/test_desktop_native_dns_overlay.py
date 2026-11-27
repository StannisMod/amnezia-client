import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "native/routing/nativedns"
BRIDGE = ROOT / "native/routing/desktopbridge/native_dns.go"
SPEC = importlib.util.spec_from_file_location(
    "native_desktop_dns_overlay", ROOT / "recipes/amnezia-xray-bindings/native_dns.py")
OVERLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAY)


class NativeDesktopDNSOverlayTest(unittest.TestCase):
    def source(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-desktop-dns-overlay-")
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name)
        (source / "go.mod").write_text((CORE / "go.mod").read_text().replace(
            "module " + OVERLAY.MODULE, "module xray_binding", 1))
        (source / "Makefile").write_text(OVERLAY.MAKE_SOURCE + "\n")
        return source

    def test_existing_runtime_overlay_is_idempotent_and_tracks_new_sources(self):
        source = self.source()
        OVERLAY.prepare(source, CORE, BRIDGE)
        first = (source / "go.mod").read_bytes()
        OVERLAY.prepare(source, CORE, BRIDGE)
        self.assertEqual(first, (source / "go.mod").read_bytes())
        self.assertEqual((source / "amnezia_native_dns.go").read_bytes(), BRIDGE.read_bytes())
        self.assertTrue((source / "amnezia-native-dns/go.sum").is_file())
        self.assertIn("$(wildcard *.go)", (source / "Makefile").read_text())
        self.assertIn("amnezia-native-dns/go.mod", (source / "Makefile").read_text())

    def test_unknown_parent_is_rejected(self):
        source = self.source()
        (source / "go.mod").write_text("module unrelated\n")
        with self.assertRaisesRegex(RuntimeError, "native desktop Xray module"):
            OVERLAY.prepare(source, CORE, BRIDGE)

    def test_shared_dependency_upgrade_is_rejected(self):
        source = self.source()
        module = source / "go.mod"
        module.write_text(module.read_text().replace("github.com/miekg/dns v1.1.72",
                                                    "github.com/miekg/dns v1.1.71"))
        with self.assertRaisesRegex(RuntimeError, "change an existing Xray dependency"):
            OVERLAY.prepare(source, CORE, BRIDGE)

    def test_partial_module_overlay_is_rejected(self):
        source = self.source()
        module = source / "go.mod"
        module.write_text(module.read_text() + "\nrequire " + OVERLAY.MODULE + " v1.0.0\n")
        with self.assertRaisesRegex(RuntimeError, "Inconsistent native DNS module"):
            OVERLAY.prepare(source, CORE, BRIDGE)

    def test_unknown_make_entry_is_rejected(self):
        source = self.source()
        (source / "Makefile").write_text("SOURCES := unknown.go\n")
        with self.assertRaisesRegex(RuntimeError, "make dependency entry"):
            OVERLAY.prepare(source, CORE, BRIDGE)
