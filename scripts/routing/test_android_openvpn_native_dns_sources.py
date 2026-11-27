"""Small source-isolation checks; no toolchain/module/build-tree copies."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "prepare_cloak_dns", ROOT / "recipes/openvpn-pt-android/prepare_cloak_dns.py")
OVERLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAY)


class CloakDNSIsolationTest(unittest.TestCase):
    def test_import_identity_changes_but_logic_and_strings_do_not(self):
        source = b'''package crypto
import (
    "golang.org/x/crypto/chacha20"
    alias "golang.org/x/sys/cpu"
    "crypto/tls"
)
import "github.com/cbeuw/Cloak/internal/common"
import std "golang.org/x/net/proxy"
//go:linkname private golang.org/x/crypto/chacha20.block
//go:linkname runtimeLink runtime.nanotime
var label = "golang.org/x/crypto/chacha20"
func protocol() string { return "TLS remains unchanged" }
'''
        result = OVERLAY.isolate_imports(source, {
            "golang.org/x/crypto": {}, "golang.org/x/sys": {}, "golang.org/x/net": {}})
        prefix = OVERLAY.NAMESPACE.encode()
        self.assertIn(b'"' + prefix + b'golang.org/x/crypto/chacha20"', result)
        self.assertIn(b'alias "' + prefix + b'golang.org/x/sys/cpu"', result)
        self.assertIn(b'//go:linkname private ' + prefix + b'golang.org/x/crypto/chacha20.block', result)
        self.assertIn(b'//go:linkname runtimeLink runtime.nanotime', result)
        self.assertIn(b'var label = "golang.org/x/crypto/chacha20"', result)
        self.assertIn(b'import "github.com/cbeuw/Cloak/internal/common"', result)
        self.assertIn(b'"crypto/tls"', result)
        self.assertIn(b'return "TLS remains unchanged"', result)

    def test_reapplication_is_refused(self):
        source = b'package a\nimport "' + OVERLAY.NAMESPACE.encode() + b'golang.org/x/sys/unix"\n'
        with self.assertRaisesRegex(ValueError, "already namespaced"):
            OVERLAY.isolate_imports(source, {"golang.org/x/sys": {}})

    def test_module_name_prefix_does_not_match_another_module(self):
        source = b'package a\nimport "golang.org/x/syscall"\n'
        self.assertEqual(OVERLAY.isolate_imports(source, {"golang.org/x/sys": {}}), source)

    def test_json_stream_cannot_accept_trailing_garbage(self):
        self.assertEqual(list(OVERLAY.json_stream(' {"a":1}\n {"b":2}\n')), [{"a": 1}, {"b": 2}])
        with self.assertRaises(ValueError):
            list(OVERLAY.json_stream('{"a":1}\ntrailing'))


if __name__ == "__main__":
    unittest.main()
