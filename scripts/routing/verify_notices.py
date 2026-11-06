#!/usr/bin/env python3
"""Verify notices inside a built APK/app or an actual installed client."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile


def verify(inventory, bundle, profile=None):
    row = json.loads(inventory)
    assert row['schema_version'] == 1 and row['modules'] and not row['missing_notices']
    assert hashlib.sha256(bundle).hexdigest() == row['bundle_sha256'], 'notice bundle checksum mismatch'
    assert all(m['notices'] and m['sum'].startswith('h1:') for m in row['modules'])
    assert any(m['source_module'] == 'github.com/sagernet/sing-box' for m in row['modules'])
    assert any(m['source_module'] == 'github.com/amnezia-vpn/amneziawg-go/v3' for m in row['modules'])
    lock=json.loads((Path(__file__).resolve().parents[2]/'native/routing/internal/builddeps/lock.json').read_text())
    provenance=row.get('tcp_recovery',{})
    selected=provenance.get('profile')
    assert selected in lock['profiles'] and (profile is None or selected==profile), 'wrong TCP dependency scope'
    pin=lock['profiles'][selected]
    assert provenance.get('fix_id')==lock['fix_id']
    assert all(provenance.get(key)==value for key,value in pin.items()), 'TCP provenance does not match lock'
    matches=[m for m in row['modules'] if m['module']=='gvisor.dev/gvisor']
    assert len(matches)==1, 'missing TCP fork notices'
    module=matches[0]
    assert (module['source_module'],module['version'],module['sum'])==(pin['module'],pin['version'],pin['sum'])
    assert any(n['path']=='NOTICE-AMNEZIA' and n['sha256']==pin['source_sha256']['NOTICE-AMNEZIA'] for n in module['notices']), 'backport notice missing'
    if selected=='apple':
        archive=row.get('tcp_recovery_archive') or {}
        assert archive.get('profile')=='apple' and archive.get('fix_id')==lock['fix_id']
        assert all(archive.get(key)==value for key,value in pin.items()), 'Apple archive identity mismatch'
        assert len(archive.get('archive_sha256',''))==64, 'Apple archive checksum missing'


    return {'modules': len(row['modules']), 'bundle_sha256': row['bundle_sha256'], 'scope': row['scope'], 'tcp_recovery': provenance}


def directory(root, profile=None):
    root = Path(root)
    return verify((root / 'inventory.json').read_bytes(), (root / 'THIRD_PARTY_NOTICES.txt').read_bytes(), profile)


def apk(path):
    with zipfile.ZipFile(path) as archive:
        return verify(archive.read('assets/routing-licenses/inventory.json'),
                      archive.read('assets/routing-licenses/THIRD_PARTY_NOTICES.txt'), 'desktop_android')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    print(json.dumps(apk(args.path) if args.path.suffix == '.apk' else directory(args.path)))
