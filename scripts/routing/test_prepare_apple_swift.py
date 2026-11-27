import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("prepare_apple_swift.py")
SPEC = importlib.util.spec_from_file_location("prepare_apple_swift", SCRIPT)
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class PrepareSwiftTest(unittest.TestCase):
    def test_only_settings_wait_is_changed(self):
        with tempfile.TemporaryDirectory(prefix="native-swift-settings-") as temporary:
            source, output = Path(temporary, "source.swift"), Path(temporary, "adapter.swift")
            source.write_text("before\n" + PREPARE.ORIGINAL + "\nafter\n")
            PREPARE.prepare(source, output)
            self.assertEqual(source.read_text(), "before\n" + PREPARE.ORIGINAL + "\nafter\n")
            self.assertEqual(output.read_text(), "before\n" + PREPARE.REPLACEMENT + "\nafter\n")
            self.assertIn("NativeNetworkSettingsResult", output.read_text())
            self.assertIn("else if requiresConfirmation", output.read_text())
            self.assertIn('NSError(domain: "NativeNetworkSettingsConfirmation"', output.read_text())

    def test_changed_or_duplicate_entry_is_rejected(self):
        for content in ["unknown adapter", PREPARE.ORIGINAL * 2]:
            with tempfile.TemporaryDirectory(prefix="native-swift-settings-") as temporary:
                source, output = Path(temporary, "source.swift"), Path(temporary, "adapter.swift")
                source.write_text(content)
                with self.assertRaisesRegex(RuntimeError, "settings completion entry point"):
                    PREPARE.prepare(source, output)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
