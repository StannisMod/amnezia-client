#!/usr/bin/env python3
"""Reject stale packaged Qt/Kotlin hosts while permitting native-only probes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from android_host_sources import changed_host_sources


class HostCompatibility(unittest.TestCase):
    def test_real_git_changes_are_classified(self):
        cases = {
            'client/core/vpn.cpp': True,
            'client/ui/qml/Page.qml': True,
            'client/server_scripts/awg/start.sh': True,
            'client/android/wireguard/src/main/kotlin/Host.kt': True,
            'recipes/libagw/conanfile.py': True,
            'cmake/Android.cmake': True,
            'deploy/build.sh': True,
            'CMakeLists.txt': True,
            'native/routing/engine/runtime.go': False,
            'scripts/routing/android/Probe.java': False,
            'client/tests/migration/test_agent.py': False,
            'client/android/wireguard/src/test/kotlin/HostTest.kt': False,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                    *args], cwd=root, text=True)
            git('init', '-q')
            for name in cases:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('baseline\n')
            git('add', '.')
            git('commit', '-qm', 'baseline')
            baseline = git('rev-parse', 'HEAD').strip()
            for name, incompatible in cases.items():
                with self.subTest(path=name):
                    (root / name).write_text('changed\n')
                    git('add', name)
                    git('commit', '-qm', 'change')
                    self.assertEqual(bool(changed_host_sources(baseline, root)), incompatible)
                    git('reset', '--hard', baseline)


if __name__ == '__main__':
    unittest.main()
