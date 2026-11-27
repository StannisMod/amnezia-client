"""Measure cross-process exclusion on both native Windows and POSIX caches."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lab_cache import Cache


@unittest.skipUnless(os.name == "nt", "nonblocking Windows workspace lock contract")
class WindowsWorkspaceLockTest(unittest.TestCase):
    def test_competing_process_cannot_enter_and_release_allows_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = (
                "import sys; from lab_cache import Cache\n"
                "with Cache(sys.argv[1]).workspace('owned'): print('entered')\n")
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).parent))
            def child():
                return subprocess.run([sys.executable, "-B", "-c", script, temporary],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            with Cache(temporary).workspace("owned"):
                denied = child()
                self.assertNotEqual(denied.returncode, 0)
                self.assertNotIn(b"entered", denied.stdout)
                self.assertIn(b"PermissionError", denied.stderr)
            allowed = child()
            self.assertEqual(allowed.returncode, 0, allowed.stderr.decode(errors="replace"))
            self.assertEqual(allowed.stdout.strip(), b"entered")


if __name__ == "__main__":
    unittest.main()
