#!/usr/bin/env python3
"""Run the existing per-app acceptance in an owned disposable managed profile."""
import re
import subprocess
import sys
import time
from pathlib import Path


def adb(*args, timeout=45):
    return subprocess.check_output(['adb', *args], text=True, timeout=timeout).strip()


def main():
    driver = Path(__file__).with_name('run_android_acceptance.py')
    arguments = sys.argv[1:]
    if '--help' in arguments:
        return subprocess.call([sys.executable, str(driver), '--help'])
    assert not any(value == '--android-user' or value.startswith('--android-user=') for value in arguments), 'profile is created by this wrapper'
    assert adb('shell', 'getprop', 'ro.kernel.qemu') == '1', 'only disposable emulators are supported'
    adb('root'); adb('wait-for-device')
    assert adb('shell', 'id', '-u') == '0', 'rooted emulator required'
    created = adb('shell', 'pm', 'create-user', '--profileOf', '0', '--managed', 'AmneziaRoutingTest')
    match = re.search(r'Success: created user id (\d+)', created)
    assert match, 'managed test profile was not created'
    profile = match[1]
    assert profile != '0'
    try:
        assert 'Success' in adb('shell', 'am', 'start-user', '-w', profile)
        return subprocess.call([sys.executable, str(driver), *arguments,
                                '--app-policy-only', '--package-lifecycle', '--android-user', profile])
    finally:
        # remove-user also stops managed users whose parent cannot be stopped.
        assert 'Success' in adb('shell', 'pm', 'remove-user', profile), 'test profile cleanup failed'
        deadline = time.monotonic() + 5
        while re.search(r'UserInfo\{' + profile + ':', adb('shell', 'pm', 'list', 'users')):
            assert time.monotonic() < deadline, 'test profile removal did not finish'
            time.sleep(0.1)


if __name__ == '__main__':
    sys.exit(main())
