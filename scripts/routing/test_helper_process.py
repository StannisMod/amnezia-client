#!/usr/bin/env python3
"""Real-pipe regression for status backpressure during helper shutdown."""
import fcntl
import subprocess
import sys
import unittest

from helper_process import stop_helper


class HelperShutdown(unittest.TestCase):
    def child(self, ending=""):
        process = subprocess.Popen(
            [sys.executable, "-c",
             "import sys\n"
             "sys.stdout.write('x' * (1024 * 1024)); sys.stdout.flush()\n"
             "command = sys.stdin.readline()\n"
             "sys.stderr.write('stop' if command == 'stop\\n' else 'eof')\n" + ending],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        self.addCleanup(self.cleanup, process)
        fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        return process

    @staticmethod
    def cleanup(process):
        if process.poll() is None:
            process.kill()
        process.communicate()

    def test_old_wait_deadlocks_but_drain_releases_same_process(self):
        process = self.child()
        process.stdin.write("stop\n")
        process.stdin.flush()
        with self.assertRaises(subprocess.TimeoutExpired):
            process.wait(timeout=0.2)
        output, errors = stop_helper(process, graceful=False)
        self.assertEqual(len(output), 1024 * 1024)
        self.assertEqual(errors, "stop")

    def test_graceful_stop_drains_status(self):
        output, errors = stop_helper(self.child())
        self.assertEqual(len(output), 1024 * 1024)
        self.assertEqual(errors, "stop")

    def test_pipe_loss_is_eof_not_graceful_stop(self):
        _, errors = stop_helper(self.child(), graceful=False)
        self.assertEqual(errors, "eof")

    def test_nonzero_exit_is_not_accepted(self):
        with self.assertRaises(AssertionError):
            stop_helper(self.child("\nsys.exit(7)\n"))

    def test_timeout_is_not_extended_or_accepted(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            stop_helper(self.child("\nimport time; time.sleep(60)\n"), timeout=0.2)


if __name__ == "__main__":
    unittest.main()
