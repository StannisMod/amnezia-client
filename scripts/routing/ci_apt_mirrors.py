#!/usr/bin/env python3
"""Use direct Ubuntu mirrors on disposable GitHub runners."""
import argparse
import os
import urllib.request
from pathlib import Path


def select_mirror(codename):
    candidates = ('https://archive.ubuntu.com/ubuntu',
                  'https://mirrors.edge.kernel.org/ubuntu',
                  'https://ubuntu.osuosl.org/ubuntu')
    for base in candidates:
        try:
            for suite in (codename, codename+'-security'):
                with urllib.request.urlopen(base+'/dists/'+suite+'/InRelease', timeout=8) as response:
                    assert response.read(100).startswith(b'-----BEGIN PGP SIGNED MESSAGE-----')
            print('Selected reachable Ubuntu mirror',base)
            return base
        except (OSError,AssertionError) as error:
            print('Mirror unavailable',base,type(error).__name__)
    raise RuntimeError('No Ubuntu mirror passed the signed-release availability probe')


def configure(root, mirror=None):
    apt = root / 'etc/apt'
    replacements = {
        'mirror+file:/etc/apt/apt-mirrors-security.txt': 'https://security.ubuntu.com/ubuntu',
        'mirror+file:/etc/apt/apt-mirrors.txt': 'https://archive.ubuntu.com/ubuntu',
        'http://azure.archive.ubuntu.com/ubuntu': 'https://archive.ubuntu.com/ubuntu',
        'https://azure.archive.ubuntu.com/ubuntu': 'https://archive.ubuntu.com/ubuntu',
    }
    if mirror:
        replacements.update({
            'https://archive.ubuntu.com/ubuntu':mirror,
            'http://archive.ubuntu.com/ubuntu':mirror,
            'https://security.ubuntu.com/ubuntu':mirror,
            'http://security.ubuntu.com/ubuntu':mirror,
        })
        for key in list(replacements): replacements[key]=mirror
    sources = [apt / 'sources.list' , *sorted((apt / 'sources.list.d').glob('*.list')),
               *sorted((apt / 'sources.list.d').glob('*.sources'))]
    for path in sources:
        if not path.is_file():
            continue
        original = path.read_text()
        updated = original
        for old, new in replacements.items():
            updated = updated.replace(old, new)
        if updated != original:
            path.write_text(updated)
            print('Updated Ubuntu mirror in', path)
    options = apt / 'apt.conf.d/80amnezia-ci-network'
    options.parent.mkdir(parents=True, exist_ok=True)
    options.write_text('Acquire::Retries "3";\nAcquire::http::Timeout "20";\nAcquire::https::Timeout "20";\nAPT::Update::Error-Mode "any";\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path('/'))
    args = parser.parse_args()
    if args.root == Path('/') and not (os.environ.get('GITHUB_ACTIONS') == 'true' and
                                      os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'):
        parser.error('system mirror changes are scoped to disposable GitHub-hosted runners')
    mirror=None
    if args.root==Path('/'):
        release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        mirror=select_mirror(release['VERSION_CODENAME'].strip('"'))
    configure(args.root,mirror)
