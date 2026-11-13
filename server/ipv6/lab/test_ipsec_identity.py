#!/usr/bin/env python3
"""Check old -> new IPsec NSS identities in disposable, unprivileged containers.

Images must already be local and pinned by digest. Only freshly generated test
keys enter the temporary directory; no host VPN or certificate store is read.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-image', required=True)
    parser.add_argument('--new-image', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    for image in (args.old_image, args.new_image):
        if '@sha256:' not in image:
            parser.error('use immutable image digests')
    observations = {}
    with tempfile.TemporaryDirectory(prefix='amnezia-ipsec-identity-') as directory:
        root = Path(directory)

        def phase(image, script):
            return run('docker', 'run', '--rm', '--pull=never', '--network', 'none',
                       '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
                       '--user', f'{os.getuid()}:{os.getgid()}', '--env', 'HOME=/fixture',
                       '--mount', f'type=bind,src={root},dst=/fixture',
                       '--entrypoint', 'sh', image, '-ec', script)

        phase(args.old_image, '''
mkdir /fixture/db
certutil -N --empty-password -d sql:/fixture/db
dd if=/dev/urandom of=/fixture/noise bs=1024 count=1 2>/dev/null
printf 'y\n\nN\n' | certutil -S -x -n migration-ca -s 'CN=Amnezia migration CA' \
    -k rsa -g 2048 -m 1 -v 1 -d sql:/fixture/db -t 'CT,,' -2 -z /fixture/noise
certutil -S -c migration-ca -n migration-client -s 'CN=Amnezia migration client' \
    -k rsa -g 2048 -m 2 -v 1 -d sql:/fixture/db -t ',,' -z /fixture/noise \
    --keyUsage digitalSignature --extKeyUsage clientAuth
certutil -S -c migration-ca -n migration-server -s 'CN=198.51.100.1' \
    -k rsa -g 2048 -m 3 -v 1 -d sql:/fixture/db -t ',,' -z /fixture/noise \
    --keyUsage digitalSignature,keyEncipherment --extKeyUsage serverAuth --extSAN ip:198.51.100.1
''')
        for name, image in (('old', args.old_image), ('new', args.new_image)):
            version = phase(image, 'ipsec --version').strip()
            observations[name] = {'image': image, 'version': version}
            # The old runtime uses OpenSSL 1.1; OpenSSL 3 may need the legacy
            # provider for NSS's older PKCS#12 encryption algorithms.
            legacy = '-legacy' if name == 'new' else ''
            phase(image, f'''
umask 077
for identity in ca client server; do
    certutil -L -d sql:/fixture/db -n migration-$identity -r > /fixture/{name}-$identity.der
    pk12util -o /fixture/{name}-$identity.p12 -n migration-$identity -d sql:/fixture/db -W fixture-only-password -K ''
    openssl pkcs12 {legacy} -in /fixture/{name}-$identity.p12 -passin pass:fixture-only-password \
        -nodes -nocerts -out /fixture/{name}-$identity-key.pem
    openssl pkey -in /fixture/{name}-$identity-key.pem -outform DER -out /fixture/{name}-$identity-key.der
done
''')
            observations[name]['fingerprints'] = {
                kind: hashlib.sha256((root / f'{name}-{kind}.der').read_bytes()).hexdigest()
                for kind in ('ca', 'ca-key', 'client', 'client-key', 'server', 'server-key')
            }
        assert observations['old']['fingerprints'] == observations['new']['fingerprints'], \
            'NSS migration changed a CA/client/server certificate or private key'
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'status': 'PASS', **observations}, indent=2) + '\n')
    print('PASS: newer IPsec runtime reads old NSS database; CA/client/server certificates and private keys unchanged')


if __name__ == '__main__':
    main()
