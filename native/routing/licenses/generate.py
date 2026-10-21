#!/usr/bin/env python3
"""Bundle actual notices from a declared, checksum-verified Go build modules.

Over-inclusive by design: module graph notices include optional platforms and
packages. This does not classify license compatibility or cover other app SDKs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def command(go, module, *args):
    return subprocess.check_output([go, *args], cwd=module, text=True,
                                   env={**os.environ, 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off'}, timeout=300)


def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        yield value
        text = text.lstrip()[end:]


def notices(root):
    root = Path(root).resolve()
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.') and not (Path(base) / d).is_symlink())
        for name in sorted(files):
            path = Path(base) / name
            if (not path.is_symlink() and path.suffix.lower() in ('', '.txt', '.md', '.rst', '.html', '.license')
                    and (name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'PATENTS', 'COPYRIGHT'))
                         or name.upper().endswith(('-LICENSE', '-LICENCE', '-NOTICE')))):
                yield path.relative_to(root).as_posix(), path.read_bytes()


def generate(module, output, go='go', host_root=None):
    module, output = Path(module).resolve(), Path(output).resolve()
    if output == module or module in output.parents:
        # Reproducible inventories must never recursively include their output.
        raise ValueError('license output must be outside the source module')
    print('Resolving pinned module notices', flush=True)
    command(go, module, 'mod', 'download')
    command(go, module, 'mod', 'verify')
    required = json.loads(command(go, module, 'mod', 'edit', '-json')).get('Require', [])
    rows = list(objects(command(go, module, 'list', '-m', '-json', *[row['Path'] for row in required])))
    texts, inventory, missing = {}, [], []

    def add_notice(path, data):
        digest = hashlib.sha256(data).hexdigest()
        texts[digest] = data.decode('utf-8', errors='strict')
        return {'path': path, 'sha256': digest}

    for original in sorted(rows, key=lambda row: row['Path']):
        if original.get('Main'):
            continue
        row = original.get('Replace', original)
        if not row.get('Version'):
            # The local routing module is licensed with the containing app;
            # its direct upstream notices are already in the resolved graph.
            if original['Path'] != 'github.com/StannisMod/amnezia-client/native/routing':
                raise ValueError('unrecognized local replacement: ' + original['Path'])
            continue
        print('Notice: ' + row['Path'] + '@' + row['Version'], flush=True)
        downloaded = json.loads(command(go, module, 'mod', 'download', '-json', row['Path'] + '@' + row['Version']))
        if downloaded.get('Error') or not downloaded.get('Sum'):
            raise ValueError('unverified module: ' + row['Path'])
        found = [add_notice(name, data) for name, data in notices(downloaded['Dir'])]
        if not found:
            missing.append(row['Path'] + '@' + row['Version'])
        inventory.append({'module': original['Path'], 'source_module': row['Path'], 'version': row['Version'],
                          'sum': downloaded['Sum'], 'notices': found})
    goroot = Path(command(go, module, 'env', 'GOROOT').strip())
    runtime_notices = [add_notice(name, (goroot / name).read_bytes()) for name in ('LICENSE', 'PATENTS')]
    runtime_notices += [add_notice('src/vendor/' + name, data) for name, data in notices(goroot / 'src/vendor')]
    host_notices = [add_notice(name, data) for name, data in notices(host_root)] if host_root else []
    if host_root and not host_notices:
        raise ValueError('native host sources contain no license notices')
    if missing:
        raise ValueError('modules without notices: ' + ', '.join(missing))
    output.mkdir(parents=True, exist_ok=True)
    manifest = {'schema_version': 1, 'scope': 'declared build-module graph and Go runtime; excludes other app SDKs',
                'go_version': command(go, module, 'version').strip(), 'modules': inventory,
                'runtime_notices': runtime_notices, 'host_notices': host_notices, 'missing_notices': missing}
    (output / 'inventory.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    lines = ['ROUTING ENGINE THIRD-PARTY NOTICES', '',
             'Pinned source modules, versions, checksums and notice paths: inventory.json.',
             'This bundle covers the resolved Go graph and runtime, not unrelated application SDKs.', '']
    for row in inventory:
        lines.append(row['source_module'] + '@' + row['version'])
        lines.extend('  ' + n['path'] + ' -> SHA256 ' + n['sha256'] for n in row['notices'])
    lines.append('\nGo runtime notices:')
    lines.extend('  ' + n['path'] + ' -> SHA256 ' + n['sha256'] for n in runtime_notices)
    lines.append('\nNative platform host notices:')
    lines.extend('  ' + n['path'] + ' -> SHA256 ' + n['sha256'] for n in host_notices)
    for digest, content in sorted(texts.items()):
        lines.extend(['\n' + '=' * 72, 'SHA256 ' + digest, '=' * 72, content])
    bundle = output / 'THIRD_PARTY_NOTICES.txt'
    bundle.write_text('\n'.join(lines) + '\n')
    manifest['bundle_sha256'] = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (output / 'inventory.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'modules': len(inventory), 'unique_notices': len(texts), 'missing_notices': missing}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--host-root', type=Path)
    args = parser.parse_args()
    generate(args.module, args.output, args.go, args.host_root)
