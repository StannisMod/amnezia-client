#!/usr/bin/env python3
"""Run the packaged helper installer only in the disposable nested daemon."""
import hashlib
import json
import subprocess


def run(*args):
    result = subprocess.run(args, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f'helper installer fixture command failed: {args[:2]}')
    return result.stdout


labels = json.loads(run('docker', 'info', '--format', '{{json .Labels}}'))
assert 'amnezia.test-environment=disposable' in labels
image = run('docker', 'inspect', '-f', '{{.Image}}', 'amnezia-connection-updates').decode().strip()


def canonical_native(raw):
    # Native peers have no defined enumeration order. Preserve every field and
    # peer association while comparing sections independent of that order.
    sections = []
    for section in raw.split(b'['):
        if not section.strip():
            continue
        lines = section.splitlines()
        sections.append((lines[0].strip(), tuple(sorted(line.strip() for line in lines[1:] if line.strip()))))
    return tuple(sorted(sections))


def snapshot(container, tool, interface, path):
    # Never emit keys/configuration in assertion diagnostics.
    return (
        run('docker', 'inspect', '-f', '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}', container),
        hashlib.sha256(run('docker', 'exec', container, 'cat', path)).digest(),
        run('docker', 'exec', container, tool, 'showconf', interface),
        run('docker', 'exec', container, 'ip', '-o', 'addr', 'show', 'dev', interface),
    )


protocols = (
    ('amnezia-wireguard', 'wg', 'wg0', '/opt/amnezia/wireguard/wg0.conf'),
    ('amnezia-awg2', 'awg', 'awg0', '/opt/amnezia/awg/awg0.conf'),
)
before = [snapshot(*protocol) for protocol in protocols]
for attempt in range(2):
    run('sh', '/tmp/helper-install.sh', '--install-protocol-helpers', image, '/tmp/helper-install-stage')
    for index, protocol in enumerate(protocols):
        after = snapshot(*protocol)
        for field, old, new in zip(('container process', 'stored config', 'native config', 'interface addresses'), before[index], after):
            if field == 'native config':
                if old != new and canonical_native(old) == canonical_native(new):
                    print('Native peer enumeration changed order; all fields and peer associations preserved')
                old, new = canonical_native(old), canonical_native(new)
            assert old == new, f'installer changed {field} for {protocol[0]}'
        container = protocol[0]
        receipt = json.loads(run('docker', 'exec', container, 'cat', '/opt/amnezia/config-helper.amnezia-owner'))
        binary_hash = hashlib.sha256(run('docker', 'exec', container, 'cat', '/opt/amnezia/config-helper')).hexdigest()
        assert receipt == {'version': 1, 'installed': binary_hash, 'candidate': binary_hash}
        assert run('docker', 'exec', container, 'stat', '-c', '%a', '/opt/amnezia/config-helper').strip() == b'700'
print('PASS: packaged helper installation/retry preserves WG/AWG container identity, process, native config and addresses')
