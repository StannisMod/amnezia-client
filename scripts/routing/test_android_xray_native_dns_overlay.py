"""Source-bound overlay checks; these are not Android backend acceptance."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "android_xray_native_dns", ROOT / "recipes/amnezia-libxray/native_dns.py")
OVERLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAY)


class AndroidXrayNativeDnsOverlayTest(unittest.TestCase):
    def source(self):
        upstream = os.environ.get("AMNEZIA_ANDROID_XRAY_SOURCE")
        engine = os.environ.get("AMNEZIA_ANDROID_TUN2SOCKS_SOURCE")
        self.assertTrue(upstream and engine, "Provide the actual cached native source paths")
        temporary = tempfile.TemporaryDirectory(prefix="android-xray-dns-", dir="/tmp/opencode")
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "source"
        shutil.copytree(upstream, source)
        return source, Path(engine)

    def apply(self, source, engine):
        OVERLAY.apply(source, engine, ROOT / "recipes/amnezia-libxray",
                      ROOT / "native/routing/nativedns")

    def test_pinned_graph_and_single_native_owner(self):
        source, engine = self.source()
        sums = (source / "go.sum").read_bytes()
        mod = (source / "go.mod").read_text()
        original_engine = (engine / "engine/engine.go").read_bytes()
        self.apply(source, engine)
        self.assertEqual(sums, (source / "go.sum").read_bytes())
        self.assertEqual(mod + "\nreplace github.com/amnezia-vpn/amnezia-tun2socks/v2 => "
                         "./amnezia-native-tun2socks\n", (source / "go.mod").read_text())
        self.assertEqual(original_engine, (engine / "engine/engine.go").read_bytes())
        changed = (source / "amnezia-native-tun2socks/engine/engine.go").read_text()
        self.assertEqual(changed.count("parseDevice(k.Device,"), 1)
        self.assertIn("_nativeDNSProxy(_defaultProxy)", changed)
        wrapper = (source / "tun2socks_wrapper.go").read_text()
        self.assertLess(wrapper.index("quiesceNativeDNS()"), wrapper.index("err := engine.StopTun2Socks()"))
        self.assertIn("if err == nil { closeNativeDNS() }", wrapper)
        controller = (source / "controller_android.go").read_text()
        self.assertEqual(controller.count("nativeDNSControl(network, address)"), 2)

    def test_unknown_native_wrapper_refuses_before_writes(self):
        source, engine = self.source()
        path = source / "tun2socks_wrapper.go"
        path.write_text(path.read_text() + "\n// unrecognized upstream change\n")
        before = (source / "go.mod").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "Unexpected native Android source"):
            self.apply(source, engine)
        self.assertEqual(before, (source / "go.mod").read_bytes())
        self.assertFalse((source / "amnezia-native-tun2socks").exists())

    def test_reapplication_refuses_without_overwriting_owner(self):
        source, engine = self.source()
        self.apply(source, engine)
        path = source / "native_dns_android.go"
        path.write_text(path.read_text() + "\n// retained local work\n")
        before = path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "already modified native engine"):
            self.apply(source, engine)
        self.assertEqual(before, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
