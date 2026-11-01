#!/usr/bin/env python3
"""Verify notices inside a built APK/app or an actual installed client."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile


def verify(inventory, bundle):
    row = json.loads(inventory)
    assert row['schema_version'] == 1 and row['modules'] and not row['missing_notices']
    assert hashlib.sha256(bundle).hexdigest() == row['bundle_sha256'], 'notice bundle checksum mismatch'
    assert all(m['notices'] and m['sum'].startswith('h1:') for m in row['modules'])
    assert any(m['source_module'] == 'github.com/sagernet/sing-box' for m in row['modules'])
    assert any(m['source_module'] == 'github.com/amnezia-vpn/amneziawg-go/v3' for m in row['modules'])
    return {'modules': len(row['modules']), 'bundle_sha256': row['bundle_sha256'], 'scope': row['scope']}


def directory(root):
    root = Path(root)
    return verify((root / 'inventory.json').read_bytes(), (root / 'THIRD_PARTY_NOTICES.txt').read_bytes())


def apk(path):
    with zipfile.ZipFile(path) as archive:
        return verify(archive.read('assets/routing-licenses/inventory.json'),
                      archive.read('assets/routing-licenses/THIRD_PARTY_NOTICES.txt'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    print(json.dumps(apk(args.path) if args.path.suffix == '.apk' else directory(args.path)))
