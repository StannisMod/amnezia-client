#!/usr/bin/env python3
"""Use direct Ubuntu mirrors on disposable GitHub runners."""
import argparse
import os
from pathlib import Path


def configure(root):
    apt = root / 'etc/apt'
    replacements = {
        'mirror+file:/etc/apt/apt-mirrors-security.txt': 'https://security.ubuntu.com/ubuntu',
        'mirror+file:/etc/apt/apt-mirrors.txt': 'https://archive.ubuntu.com/ubuntu',
        'http://azure.archive.ubuntu.com/ubuntu': 'https://archive.ubuntu.com/ubuntu',
        'https://azure.archive.ubuntu.com/ubuntu': 'https://archive.ubuntu.com/ubuntu',
    }
    sources = [apt / 'sources.list', *sorted((apt / 'sources.list.d').glob('*.list')),
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
    configure(args.root)
