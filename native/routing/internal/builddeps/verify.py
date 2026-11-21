#!/usr/bin/env python3
"""Verify the resolved Go graph and immutable TCP fork before packaging."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct

LOCK = Path(__file__).with_name('lock.json')
SCOPES = {
    'github.com/StannisMod/amnezia-client/native/routing': 'desktop_android',
    'github.com/amnezia-vpn/amneziawg-android': 'desktop_android',
    'github.com/amnezia-vpn/amneziawg-apple': 'apple',
}
SOURCE_FILES = {
    'pkg/tcpip/transport/tcp/snd.go', 'pkg/tcpip/transport/tcp/rack.go',
    'pkg/tcpip/transport/tcp/segment.go', 'pkg/amnezia/recovery.go', 'NOTICE-AMNEZIA',
}

PROBE_SOURCE_FILES = {
    'pkg/tcpip/transport/tcp/verified_path_probe.go',
    'pkg/tcpip/transport/tcp/tcp_state_autogen.go',
    'pkg/tcpip/adapters/gonet/verified_path_probe.go',
}
PROFILE_SOURCE_FILES = {
    'desktop_android': SOURCE_FILES | PROBE_SOURCE_FILES,
    'apple': SOURCE_FILES | PROBE_SOURCE_FILES,
}

def load_lock():
    lock = json.loads(LOCK.read_text())
    if lock.get('schema_version') != 1 or lock.get('fix_id') != 'rack-flight-v1':
        raise ValueError('unsupported TCP dependency lock')
    if set(lock['profiles']) != set(PROFILE_SOURCE_FILES):
        raise ValueError('unsupported TCP source profiles')
    for profile, pin in lock['profiles'].items():
        if set(pin['source_sha256']) != PROFILE_SOURCE_FILES[profile]:
            raise ValueError('incomplete TCP source identity')
    return lock

def run(go, module, *args):
    return subprocess.check_output([go, *args], cwd=module, text=True,
                                  env={**os.environ, 'GOTOOLCHAIN': 'local'}, timeout=300)

def verify_resolution(resolved, downloaded, pin):
    replacement = resolved.get('Replace', {})
    if (resolved.get('Path') != 'gvisor.dev/gvisor'
            or resolved.get('Version') != pin['upstream_version']
            or replacement.get('Path') != pin['module']
            or replacement.get('Version') != pin['version']):
        raise ValueError('unexpected resolved TCP dependency')
    for key, expected in [('Path', pin['module']), ('Version', pin['version']),
                          ('Sum', pin['sum']), ('GoModSum', pin['go_mod_sum'])]:
        if downloaded.get(key) != expected:
            raise ValueError('TCP source checksum/version mismatch: ' + key)
    source = Path(downloaded['Dir'])
    for relative, expected in pin['source_sha256'].items():
        path = source / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('TCP source contents changed: ' + relative)


def check(module, scope=None, go='go'):
    module = Path(module).resolve()
    lock = load_lock()
    declared = json.loads(run(go, module, 'mod', 'edit', '-json'))
    main = declared.get('Module', {}).get('Path')
    expected_scope = SCOPES.get(main)
    if expected_scope is None or (scope is not None and scope != expected_scope):
        raise ValueError('unknown or mismatched TCP build scope')
    scope = expected_scope
    pin = lock['profiles'][scope]
    if any(tag in run(go, module, 'env', 'GOFLAGS') for tag in ('amnezia_dependency_repro','amnezia_race_dependency')):
        raise ValueError('dependency reproduction tags are forbidden in release builds')
    declared_replacements = [row for row in (declared.get('Replace') or [])
                             if row['Old']['Path'] == 'gvisor.dev/gvisor']
    if (len(declared_replacements) != 1
            or declared_replacements[0]['Old'].get('Version')
            or declared_replacements[0]['New'] != {'Path': pin['module'], 'Version': pin['version']}):
        raise ValueError('main module does not declare the locked TCP replacement')
    downloaded = json.loads(run(go, module, 'mod', 'download', '-json', pin['module']+'@'+pin['version']))
    resolved = json.loads(run(go, module, 'list', '-mod=readonly', '-m', '-json', 'gvisor.dev/gvisor'))
    verify_resolution(resolved, downloaded, pin)
    run(go, module, 'mod', 'verify')
    return {'fix_id': lock['fix_id'], 'profile': scope, **pin}


def verify_info(info, scope):
    lock = load_lock()
    pin = lock['profiles'][scope]
    expected = {'mode': 'fixed', 'fix_id': lock['fix_id'], 'profile': scope,
                'upstream_version': pin['upstream_version'], 'upstream_commit': pin['upstream_commit'],
                'module': pin['module'], 'version': pin['version'], 'sum': pin['sum'], 'commit': pin['commit']}
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError('packaged backend TCP provenance mismatch')
    return info


def verify_metadata(info, scope):
    lock = load_lock()
    pin = lock['profiles'][scope]
    if SCOPES.get(info.get('Main',{}).get('Path')) != scope:
        raise ValueError('packaged backend has the wrong main module/scope')
    rows = [row for row in info.get('Deps', []) if row.get('Path') == 'gvisor.dev/gvisor']
    if len(rows) != 1:
        raise ValueError('packaged backend has no unique TCP dependency')
    row = rows[0]
    replaced = row.get('Replace', {})
    if (row.get('Version') != pin['upstream_version']
            or replaced.get('Path') != pin['module'] or replaced.get('Version') != pin['version']
            or replaced.get('Sum') != pin['sum']):
        raise ValueError('packaged backend TCP dependency is not locked')
    if any(tag in str(setting.get('Value', '')) for setting in info.get('Settings', []) if setting.get('Key') == '-tags' for tag in ('amnezia_dependency_repro','amnezia_race_dependency')):
        raise ValueError('packaged backend is a dependency reproduction build')
    return {'fix_id': lock['fix_id'], 'profile': scope, **pin}


def verify_binary_file(binary, scope, go='go'):
    # go version reads ELF/PE/Mach-O metadata; it does not execute the target.
    info = json.loads(subprocess.check_output([go, 'version', '-m', '-json', str(Path(binary).resolve())], text=True, timeout=30))
    record = verify_metadata(info, scope)
    record['binary_sha256'] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    return record


def archive_slices(data):
    """Unwrap lipo containers, validating every architecture's flat archive."""
    if data.startswith(b'!<arch>\n'):
        return [data]
    formats = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
               b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
    if data[:4] not in formats or len(data) < 8:
        raise ValueError('unsupported Go archive container')
    endian, wide = formats[data[:4]]
    count = struct.unpack_from(endian+'I', data, 4)[0]
    width = 32 if wide else 20
    table_end = 8+count*width
    if not 1 <= count <= 64 or table_end > len(data):
        raise ValueError('invalid universal archive table')
    ranges, architectures, slices = [], set(), []
    for index in range(count):
        fields = struct.unpack_from(endian+('IIQQII' if wide else 'IIIII'), data, 8+index*width)
        cpu, subtype, offset, size, alignment = fields[:5]
        if (alignment > 63 or offset % (1 << alignment) or offset < table_end
                or not size or offset+size > len(data)
                or (wide and fields[5] != 0) or (cpu, subtype) in architectures
                or any(offset < end and offset+size > start for start, end in ranges)):
            raise ValueError('invalid universal archive slice')
        content = data[offset:offset+size]
        if not content.startswith(b'!<arch>\n'):
            raise ValueError('universal archive slice is not a flat archive')
        architectures.add((cpu, subtype)); ranges.append((offset, offset+size)); slices.append(content)
    return slices


def archive_go_object(data):
    """Read the unique Go object from a flat GNU or BSD ar archive."""
    if not data.startswith(b'!<arch>\n'):
        raise ValueError('unsupported Go archive container')
    offset, names, objects = 8, b'', []
    while offset < len(data):
        header = data[offset:offset+60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('invalid archive member header')
        size = int(header[48:58].strip())
        end = offset+60+size
        if size < 0 or end > len(data):
            raise ValueError('truncated archive member')
        name = header[:16].rstrip().decode('ascii')
        content = data[offset+60:end]
        if name.startswith('#1/'):
            length = int(name[3:])
            if length < 0 or length > len(content): raise ValueError('truncated BSD archive name')
            name = content[:length].rstrip(b'\x00').decode('utf-8')
            content = content[length:]
        elif name == '//':
            names = content
        elif name.startswith('/') and name[1:].isdigit():
            start = int(name[1:])
            if start >= len(names): raise ValueError('invalid GNU archive name')
            name = names[start:].split(b'/\n', 1)[0].decode('utf-8')
        name = name.rstrip('/')
        if name.rsplit('/',1)[-1] == 'go.o': objects.append(content)
        offset = end + (size & 1)
    if len(objects) != 1:
        raise ValueError('archive has no unique Go runtime object')
    return objects[0]


def inline_build_metadata(data):
    """Decode Go 1.18+ inline build-info strings from an archive Go object.

    Static archives are intentionally skipped by `go version -m`. The format
    and 32-byte header follow the pinned Go debug/buildinfo implementation.
    We require the inline-string flag and reject unsupported encodings.
    """
    def text(at, limit):
        size, shift = 0, 0
        for _ in range(10):
            if at >= len(data): raise ValueError('truncated build-info length')
            byte = data[at]; at += 1
            size |= (byte & 127) << shift
            if byte < 128: break
            shift += 7
        else: raise ValueError('invalid build-info length')
        if size > limit or at+size > len(data): raise ValueError('truncated build-info string')
        return data[at:at+size], at+size
    magic, start, records = b'\xff Go buildinf:', 0, []
    while True:
        offset = data.find(magic, start)
        if offset < 0: break
        start = offset+len(magic)
        if offset+32 > len(data) or data[offset+14] not in (4,8) or data[offset+15] not in (2,3):
            continue  # An ordinary string literal is not a build-info header.
        try:
            version, at = text(offset+32, 256)
            encoded, _ = text(at, 8*1024*1024)
            if not version.startswith(b'go1.') or len(encoded)<32: continue
            body = encoded[16:-16].decode('utf-8')
            if not body.startswith('path\t') or not body.endswith('\n'): continue
        except (ValueError,UnicodeDecodeError):
            continue
        info = {'GoVersion':version.decode('ascii'),'Deps':[],'Settings':[]}
        previous = None
        for line in body.splitlines():
            fields = line.split('\t')
            if fields[0] in ('mod','dep') and len(fields)>=3:
                previous={'Path':fields[1],'Version':fields[2],'Sum':fields[3] if len(fields)>3 else ''}
                if fields[0]=='mod': info['Main']=previous
                else: info['Deps'].append(previous)
            elif fields[0]=='=>' and previous is not None and len(fields)>=3:
                previous['Replace']={'Path':fields[1],'Version':fields[2],'Sum':fields[3] if len(fields)>3 else ''}
            elif fields[0]=='build' and len(fields)==2:
                key, _, value = fields[1].strip('"').partition('=')
                info['Settings'].append({'Key':key,'Value':value})
        if 'Main' in info: records.append(info)
    if not records:
        raise ValueError('archive has no supported Go module build metadata')
    return records


def verify_archive_file(archive, scope):
    data = Path(archive).read_bytes()
    for content in archive_slices(data):
        records = inline_build_metadata(archive_go_object(content))
        for info in records:
            record = verify_metadata(info, scope)
    record['archive_sha256'] = hashlib.sha256(data).hexdigest()
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--scope', choices=['desktop_android', 'apple'])
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    record = check(args.module, args.scope, args.go)
    if args.binary:
        record = verify_binary_file(args.binary, record['profile'], args.go)
    if args.archive:
        record = verify_archive_file(args.archive, record['profile'])
    text = json.dumps(record, indent=2, sort_keys=True)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end='')
