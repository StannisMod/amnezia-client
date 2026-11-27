import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from check_workflow_python import check


class WorkflowPythonTest(unittest.TestCase):
    def check_fixture(self, body):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text(body)
            with contextlib.redirect_stdout(io.StringIO()):
                check(path)

    def test_routing_workflow_python_parses(self):
        path = Path(__file__).resolve().parents[2] / ".github/workflows/sing-box-routing-ci.yml"
        with contextlib.redirect_stdout(io.StringIO()):
            check(path)

    def test_invalid_python_indentation_is_rejected(self):
        with self.assertRaises(IndentationError):
            self.check_fixture("run: |\n  python3 - <<'PY'\n  import os\n   print(os.name)\n  PY\n")

    def test_missing_heredoc_terminator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing heredoc terminator"):
            self.check_fixture("run: |\n  python3 - <<'PY'\n  print('hello')\n")


if __name__ == "__main__":
    unittest.main()
