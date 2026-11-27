#!/usr/bin/env python3
"""Evaluate generated profiles with OpenVPN3 JNI extracted from a real APK.

Uses an owned emulator's app_process. No APK modification, installation, VPN
service, network change or production test hook is involved. This proves native
option initialization; optional local TLS mode also records TUN callbacks.
Neither mode proves Android TUN establishment or packet forwarding.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from zipfile import ZipFile


def run(*args, **kwargs):
    try:
        return subprocess.check_output(list(map(str, args)), text=True, stderr=subprocess.STDOUT,
                                       timeout=kwargs.pop('timeout', 60), **kwargs)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.output) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--policies', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--tls-fixture', type=Path, help='owned local server credentials; fixed emulator gateway/port only')
    parser.add_argument('--serial', default='emulator-5554')
    args = parser.parse_args()
    assert os.environ.get('AMNEZIA_ANDROID_NATIVE_CONFIG_PROBE') == 'owned-emulator'
    assert args.serial.startswith('emulator-'), 'physical devices are not permitted'
    adb = [args.sdk / 'platform-tools/adb', '-s', args.serial]
    assert run(*adb, 'shell', 'getprop', 'ro.kernel.qemu').strip() == '1'
    abi = run(*adb, 'shell', 'getprop', 'ro.product.cpu.abi').strip()
    assert abi in ('x86_64', 'x86', 'arm64-v8a', 'armeabi-v7a'), abi
    repo = Path(__file__).resolve().parents[2]
    tools = args.sdk / 'build-tools/36.0.0'
    android_jar = args.sdk / 'platforms/android-36/android.jar'
    device = '/data/local/tmp/amnezia-ovpn3-config-' + secrets.token_hex(8)
    apk_hash = hashlib.sha256(args.apk.read_bytes()).hexdigest()
    native_hashes = {}
    with tempfile.TemporaryDirectory(prefix='amnezia-ovpn3-config-') as tmp:
        work = Path(tmp)
        libs = work / 'lib'
        libs.mkdir()
        with ZipFile(args.apk) as archive:
            for name in ('libc++_shared.so', 'libck-ovpn-plugin.so', 'libovpn3.so'):
                data = archive.read(f'lib/{abi}/{name}')
                (libs / name).write_bytes(data)
                native_hashes[name] = hashlib.sha256(data).hexdigest()
        # Isolated, short-lived test credentials: native evaluation must use the
        # same default client-certificate mode as the production Kotlin caller.
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Local OpenVPN3 parser fixture', '-keyout', work / 'key.pem', '-out', work / 'cert.pem')
        cert, key = (work / 'cert.pem').read_text(), (work / 'key.pem').read_text()
        credentials = f'\n<ca>\n{cert}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n'
        if args.tls_fixture:
            fixture = json.loads(args.tls_fixture.read_text())
            assert fixture['host'] == '10.0.2.2' and fixture['port'] == 21943
            credentials = ''.join(f'\n<{tag}>\n{fixture[name]}</{tag}>\n' for tag, name in
                                  (('ca', 'ca.crt'), ('cert', 'client.crt'), ('key', 'client.key')))
        policies = json.loads(args.policies.read_text())
        profiles = {}
        for name, content in policies.items():
            # Local-settings fixtures compiled on Linux add desktop resolver
            # hooks; these three directives are absent from the Android build.
            content = '\n'.join(line for line in content.splitlines()
                                if not line.startswith(('up ', 'down ', 'script-security ')))
            profiles[name] = content + credentials
        assert 'legacy-export' in profiles and 'api-full' in profiles
        # eval_config intentionally does not reject every unknown directive;
        # use a structural negative control and also initialize native options.
        profiles['invalid-control'] = 'client\n'
        (work / 'profiles.json').write_text(json.dumps({'profiles': profiles, 'tls': bool(args.tls_fixture)}))
        classes, dex = work / 'classes', work / 'dex'
        classes.mkdir()
        dex.mkdir()
        sources = sorted((repo / 'client/android/openvpn/src/main/java').rglob('*.java'))
        sources += [repo / 'scripts/routing/android-openvpn/OpenVpnConfigProbe.java']
        run('javac', '-source', '8', '-target', '8', '-classpath', android_jar, '-d', classes, *sources)
        run(tools / 'd8', '--min-api', '28', '--lib', android_jar, '--output', dex, *sorted(classes.rglob('*.class')))
        with ZipFile(work / 'probe.jar', 'w') as archive:
            for path in dex.glob('*.dex'):
                archive.write(path, path.name)
        try:
            run(*adb, 'shell', 'mkdir', '-p', device)
            run(*adb, 'push', libs, device + '/lib')
            run(*adb, 'push', work / 'probe.jar', device + '/probe.jar')
            run(*adb, 'push', work / 'profiles.json', device + '/profiles.json')
            executable = '/system/bin/app_process64' if abi in ('x86_64', 'arm64-v8a') else '/system/bin/app_process32'
            process = subprocess.run(list(map(str, [*adb, 'shell', 'env', 'CLASSPATH=' + device + '/probe.jar',
                         'LD_LIBRARY_PATH=' + device + '/lib', 'timeout', '90' if args.tls_fixture else '30', executable, '/system/bin',
                         'org.amnezia.openvpntest.OpenVpnConfigProbe', device + '/lib', device + '/profiles.json'])),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=110 if args.tls_fixture else 60)
            output = process.stdout
            rows = [line.split('=', 1)[1] for line in output.splitlines() if line.startswith('OPENVPN3_CONFIG_PROBE=')]
            assert len(rows) == 1, (process.returncode, output)
            report = json.loads(rows[0])
            report.update({'abi': abi, 'apk_sha256': apk_hash, 'native_sha256': native_hashes,
                           'policies_sha256': hashlib.sha256(args.policies.read_bytes()).hexdigest(),
                           'not_proven': ['Android TUN configuration', 'actual VPN packet forwarding']})
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            assert report['status'] == 'PASS' and process.returncode == 0, json.dumps(report)
            print(json.dumps(report), flush=True)
        finally:
            run(*adb, 'shell', 'rm', '-rf', device)
    assert hashlib.sha256(args.apk.read_bytes()).hexdigest() == apk_hash, 'input APK was modified'


if __name__ == '__main__':
    main()
