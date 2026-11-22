import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "recipes/hev-socks5-tunnel/native_dns_filter.py"
SPEC = importlib.util.spec_from_file_location("hev_native_dns", SCRIPT)
OVERLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAY)


class HevNativeDNSTest(unittest.TestCase):
    def fixture(self):
        return "\n".join([OVERLAY.HEADER, OVERLAY.READ, OVERLAY.READY,
                          OVERLAY.FINI, OVERLAY.FINI_END, OVERLAY.STOP])

    def test_checked_reader_ready_and_stop_hooks_are_idempotent(self):
        source = self.fixture()
        result = OVERLAY.prepare(source)
        self.assertIn(OVERLAY.FILTERED_READ, result)
        self.assertIn(OVERLAY.READY_HOOK, result)
        self.assertIn(OVERLAY.JOINED_STOP, result)
        self.assertEqual(OVERLAY.prepare(result), result)
        self.assertIn('assert (res > 0 && "socks5 tunnel write event")', result)
        self.assertNotIn("usleep", result)
        self.assertNotIn("AMNEZIA_NATIVE_DNS_FILTER", source)

    def test_changed_or_duplicate_reader_fails_closed(self):
        for source in [self.fixture().replace(OVERLAY.READ, ""), self.fixture() + OVERLAY.READ]:
            with self.assertRaisesRegex(RuntimeError, "reader/lifecycle entry point"):
                OVERLAY.prepare(source)

    def test_partial_overlay_is_rejected(self):
        broken = self.fixture().replace(OVERLAY.READ, OVERLAY.FILTERED_READ)
        with self.assertRaisesRegex(RuntimeError, "Inconsistent"):
            OVERLAY.prepare(broken)

    def test_framework_activation_header_is_checked_and_idempotent(self):
        output = OVERLAY.prepare_header(OVERLAY.HEADER_ENTRY)
        self.assertEqual(output, OVERLAY.prepare_header(output))
        self.assertIn("amnezia_hev_filter_enable", output)
        with self.assertRaisesRegex(RuntimeError, "public framework header"):
            OVERLAY.prepare_header("unknown API")

    def test_recipe_helper_is_valid_python(self):
        import ast
        ast.parse((ROOT / "recipes/hev-socks5-tunnel/conanfile.py").read_text())


if __name__ == "__main__":
    unittest.main()
