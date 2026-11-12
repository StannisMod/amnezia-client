#!/usr/bin/env python3
"""Hash the original image-config bytes in a Docker save stream, not inspect JSON."""
import argparse
import hashlib
import json
import sys
import tarfile


def config_digest(stream, operating_system, architecture):
    configs = {}
    manifest = None
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            if not member.isfile() or member.size > 4 * 1024 * 1024:
                continue
            # Docker's classic config names and OCI blob names are both valid.
            if not (member.name.endswith('.json') or member.name.startswith('blobs/sha256/')):
                continue
            raw = archive.extractfile(member).read()
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                continue
            if member.name == 'manifest.json':
                manifest = value
            elif (isinstance(value, dict) and value.get('os') == operating_system
                  and value.get('architecture') == architecture
                  and isinstance(value.get('rootfs'), dict)
                  and value['rootfs'].get('type') == 'layers'):
                configs[member.name] = hashlib.sha256(raw).hexdigest()
    if not isinstance(manifest, list) or not manifest:
        raise ValueError('Docker save manifest is missing')
    selected = {configs[row['Config']] for row in manifest
                if isinstance(row, dict) and row.get('Config') in configs}
    if len(selected) != 1:
        raise ValueError('Expected exactly one image config for the selected platform')
    return 'sha256:' + selected.pop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--os', required=True)
    parser.add_argument('--arch', required=True)
    args = parser.parse_args()
    print(config_digest(sys.stdin.buffer, args.os, args.arch))
