"""Reject mismatched immutable runtime evidence before touching build metadata."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "desktop_runtime_link", Path(__file__).with_name("link_cached_desktop_service.py"))
LINK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINK)
MODULE = "github.com/StannisMod/amnezia-client/native/routing/nativedns"


class RuntimeEvidenceTest(unittest.TestCase):
    def test_measured_runtime_replaces_only_existing_runtime_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime, evidence, output = root / "runtime", root / "evidence", root / "owned"
            for path in (runtime, evidence, output / "conan"):
                path.mkdir(parents=True)
            measured = {}
            for name, key in (("amnezia_xray.a", "archive_sha256"),
                              ("amnezia_xray.h", "header_sha256")):
                data = name.encode()
                (runtime / name).write_bytes(data)
                measured[key] = hashlib.sha256(data).hexdigest()
            (evidence / "result.json").write_text(json.dumps(measured))
            (evidence / "dependency-graph.json").write_text(json.dumps({
                "compiled_before": {"existing": ["v1", "", ""]},
                "compiled_after": {"existing": ["v1", "", ""], MODULE: ["", "./local", ""]},
                "only_added_module": MODULE}))
            target = output / "conan/amnezia-xray-bindings-Targets-release.cmake"
            target.write_text('set(archive "/old/runtime/amnezia_xray.a")\n'
                              'set(include "/old/runtime")\n')
            other = output / "conan/unrelated.cmake"
            other.write_text('set(unchanged "/old/runtime")\n')
            args = ["link", "--cache", str(root), "--output", str(output),
                    "--resume", "--native-dns-runtime", str(runtime),
                    "--native-dns-evidence", str(evidence)]
            with patch.object(sys, "argv", args), patch.object(LINK.subprocess, "run") as run:
                LINK.main()
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args_list[0].args[0][:2], ["cmake", "-S"])
                self.assertIn("AmneziaVPN-service", run.call_args_list[1].args[0])
            self.assertIn(str(runtime / "amnezia_xray.a"), target.read_text())
            self.assertNotIn("/old/runtime", target.read_text())
            self.assertEqual(other.read_text(), 'set(unchanged "/old/runtime")\n')

    def test_rejects_mismatched_bytes_versions_and_unexpected_added_module(self):
        for failure in ("archive", "header", "version", "added-module"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                runtime, evidence = root / "runtime", root / "evidence"
                runtime.mkdir()
                evidence.mkdir()
                measured = {}
                for name, key in (("amnezia_xray.a", "archive_sha256"),
                                  ("amnezia_xray.h", "header_sha256")):
                    data = name.encode()
                    (runtime / name).write_bytes(data)
                    measured[key] = hashlib.sha256(data).hexdigest()
                if failure in ("archive", "header"):
                    name = "amnezia_xray.a" if failure == "archive" else "amnezia_xray.h"
                    (runtime / name).write_bytes(b"changed")
                before = {"existing": ["v1", "", ""]}
                added = "unrelated" if failure == "added-module" else MODULE
                after = {**before, added: ["", "./local", ""]}
                if failure == "version":
                    after["existing"] = ["v2", "", ""]
                (evidence / "result.json").write_text(json.dumps(measured))
                (evidence / "dependency-graph.json").write_text(json.dumps({
                    "compiled_before": before, "compiled_after": after,
                    "only_added_module": added}))
                args = ["link", "--cache", str(root), "--output", str(root / "untouched"),
                        "--resume", "--native-dns-runtime", str(runtime),
                        "--native-dns-evidence", str(evidence)]
                with patch.object(sys, "argv", args), \
                        patch.object(LINK.subprocess, "run") as run, \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        LINK.main()
                    self.assertEqual(raised.exception.code, 2)
                    run.assert_not_called()
                self.assertFalse((root / "untouched").exists())


if __name__ == "__main__":
    unittest.main()
