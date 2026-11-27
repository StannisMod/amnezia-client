import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "windows_native_dns", ROOT / "recipes/awg-windows/native_dns.py")
OVERLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAY)
HELPER = ROOT / "recipes/awg-windows/native_dns_windows.go"


class WindowsNativeDNSOverlayTest(unittest.TestCase):
    def source(self):
        temporary = tempfile.TemporaryDirectory(prefix="windows-native-dns-overlay-")
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name)
        (source / "conf").mkdir()
        (source / "tunnel/winipcfg").mkdir(parents=True)
        (source / "conf/config.go").write_text(OVERLAY.FIELD[0])
        (source / "conf/parser.go").write_text("\n".join(
            (OVERLAY.PARSER[0], OVERLAY.COPY[0], OVERLAY.VALIDATE[0])))
        (source / "conf/writer.go").write_text(OVERLAY.WRITER[0])
        (source / "tunnel/addressconfig.go").write_text(
            OVERLAY.ADDRESSES[0] + "\n" + OVERLAY.DNS[0])
        (source / "addressconfig.go").write_text(
            OVERLAY.ADDRESSES[0] + "\n\treturn ipif.Set()\n")
        return source

    def test_checked_overlay_is_idempotent(self):
        source = self.source()
        OVERLAY.prepare(source, HELPER)
        first = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*.go")}
        OVERLAY.prepare(source, HELPER)
        self.assertEqual(first, {str(p.relative_to(source)): p.read_bytes()
                                 for p in source.rglob("*.go")})
        self.assertIn("NativeDNSManaged", (source / "conf/parser.go").read_text())
        self.assertIn("AmneziaNativeDNS = true", (source / "conf/writer.go").read_text())
        self.assertIn("SetIPAddressesForFamilyWithNativeDNS",
                      (source / "tunnel/addressconfig.go").read_text())
        self.assertIn("SetIPAddressesForFamilyWithNativeDNS",
                      (source / "addressconfig.go").read_text())

    def test_changed_address_entry_rejects_without_partial_write(self):
        source = self.source()
        entry = source / "tunnel/addressconfig.go"
        entry.write_text(entry.read_text().replace("return luid.SetDNS", "return changedSetDNS"))
        original = (source / "conf/config.go").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "native Windows DNS entry"):
            OVERLAY.prepare(source, HELPER)
        self.assertEqual(original, (source / "conf/config.go").read_bytes())

    def test_unknown_existing_helper_is_not_overwritten(self):
        source = self.source()
        helper = source / "tunnel/winipcfg/native_dns_windows.go"
        helper.write_text("unknown native implementation\n")
        with self.assertRaisesRegex(RuntimeError, "preexisting"):
            OVERLAY.prepare(source, HELPER)
        self.assertEqual(helper.read_text(), "unknown native implementation\n")

    def test_late_uapi_keeps_external_dns_ownership(self):
        source = self.source()
        OVERLAY.prepare(source, HELPER)
        parser = (source / "conf/parser.go").read_text()
        self.assertIn("NativeDNSManaged: existingConfig.Interface.NativeDNSManaged", parser)
        self.assertIn("len(conf.Interface.DNS) != 0", parser)
        self.assertIn("!conf.Interface.TableOff", parser)
