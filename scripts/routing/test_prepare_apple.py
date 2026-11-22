import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "native/routing"
SPEC = importlib.util.spec_from_file_location("prepare_apple", CORE / "prepare_apple.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class PrepareAppleTest(unittest.TestCase):
    def prepare(self, entry):
        temporary = tempfile.TemporaryDirectory(prefix="native-filter-overlay-")
        self.addCleanup(temporary.cleanup)
        module = Path(temporary.name)
        (module / "api-apple.go").write_text(entry)
        (module / "Makefile").write_text("go build -ldflags=-w\n")
        return module

    def test_native_reader_is_wrapped_once_and_bridge_is_copied(self):
        module = self.prepare("dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)\n")
        PREPARE.prepare_module(CORE, module)
        self.assertEqual((module / "api-apple.go").read_text(),
                         "dev := device.NewDevice(amneziaNativeFilterTUN(tun), conn.NewStdNetBind(), logger)\n")
        self.assertEqual((module / "native_filter_apple.go").read_bytes(),
                         (CORE / "applebridge/native_filter_apple.go").read_bytes())
        self.assertIn("amnezia_apple_bridge", (module / "Makefile").read_text())
        self.assertIn("AmneziaNativePacketFilterStart", (module / "amnezia_routing.h").read_text())

    def test_changed_native_ownership_entry_is_rejected(self):
        module = self.prepare("dev := changedNativeDeviceFactory(tun)\n")
        with self.assertRaisesRegex(RuntimeError, "native AWG TUN ownership"):
            PREPARE.prepare_module(CORE, module)

    def test_multiple_native_entry_points_are_rejected(self):
        entry = "dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)\n"
        module = self.prepare(entry * 2)
        with self.assertRaisesRegex(RuntimeError, "native AWG TUN ownership"):
            PREPARE.prepare_module(CORE, module)


if __name__ == "__main__":
    unittest.main()
