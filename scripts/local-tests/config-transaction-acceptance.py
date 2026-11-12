#!/usr/bin/env python3
"""Exercise the production helper only in the disposable nested Docker daemon."""
import base64
import hashlib
import json
import subprocess


def run(*args, data=None, ok=True):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if ok and result.returncode:
        raise RuntimeError(f"fixture command failed: {args[0:3]}: {result.stderr.decode(errors='replace')}")
    return result


labels = json.loads(run('docker', 'info', '--format', '{{json .Labels}}').stdout)
assert 'amnezia.test-environment=disposable' in labels, 'requires disposable private Docker daemon'
helper = '/opt/amnezia/config-helper'
for container, binary, interface, path in (
    ('amnezia-wireguard', 'wg', 'wg0', '/opt/amnezia/wireguard/wg0.conf'),
    ('amnezia-awg2', 'awg', 'awg0', '/opt/amnezia/awg/awg0.conf'),
):
    original = run('docker', 'exec', container, 'cat', path).stdout
    candidate = original + b'\n# private configuration transaction regression\n'
    peers = sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines())

    def invoke(action, operation=None, expected=None, candidate=None, ok=True):
        request = dict(action=action, container=container)
        if operation is not None:
            request['operation'] = operation
        if expected is not None:
            request['expected'] = base64.b64encode(expected).decode()
        if candidate is not None:
            request['candidate'] = base64.b64encode(candidate).decode()
        result = run('docker', 'exec', '-i', container, helper, 'config-file-transaction',
                     data=json.dumps(request).encode(), ok=ok)
        if not ok:
            assert result.returncode and not result.stdout, 'invalid request was accepted'
            return None
        return json.loads(result.stdout)

    staged = invoke('stage', expected=original, candidate=candidate)
    operation = staged['operation']
    assert len(operation) == 64
    assert staged['originalHash'] == hashlib.sha256(original).hexdigest()
    assert staged['candidateHash'] == hashlib.sha256(candidate).hexdigest()
    assert run('docker', 'exec', container, 'cat', path).stdout == candidate
    assert run('docker', 'exec', container, 'stat', '-c', '%a', path + '.amnezia-journal').stdout.strip() == b'600'
    invoke('stage', expected=candidate, candidate=original, ok=False)
    invoke('rollback', operation='0' * 64, ok=False)
    status = invoke('status')
    assert status['operation'] == operation and status['state'] == 'candidate'
    invoke('rollback', operation=operation)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    invoke('rollback', operation=operation, ok=False)
    committed = invoke('stage', expected=original, candidate=candidate)
    assert committed['operation'] != operation
    invoke('commit', operation=committed['operation'])
    assert run('docker', 'exec', container, 'cat', path).stdout == candidate
    restore = invoke('stage', expected=candidate, candidate=original)
    invoke('commit', operation=restore['operation'])
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    def allowed():
        lines = run('docker', 'exec', container, binary, 'show', interface, 'allowed-ips').stdout.splitlines()
        peers_and_routes = []
        for line in lines:
            key, routes = line.split(b'\t', 1)
            peers_and_routes.append((key, tuple(sorted(routes.replace(b',', b' ').split()))))
        return sorted(peers_and_routes)

    original_allowed = allowed()
    ipv4 = b'10.77.0.3/32' if binary == 'wg' else b'10.88.0.3/32'
    added_ipv6 = b'fd77::abcd/128' if binary == 'wg' else b'fd88::abcd/128'
    assert original.count(ipv4) == 1
    live_candidate = original.replace(ipv4, ipv4 + b', ' + added_ipv6, 1)
    # Failure between persisted stage and native apply must recover both states.
    unapplied = invoke('stage', expected=original, candidate=live_candidate)
    assert allowed() == original_allowed
    invoke('rollback-live', operation=unapplied['operation'])
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    live = invoke('stage', expected=original, candidate=live_candidate)
    invoke('apply', operation='0' * 64, ok=False)
    assert allowed() == original_allowed
    invoke('apply', operation=live['operation'])
    assert allowed() != original_allowed
    assert any(added_ipv6 in routes for _, routes in allowed())
    invoke('rollback-live', operation=live['operation'])
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    # The native parser really rejects this candidate; the durable journal survives.
    invalid = invoke('stage', expected=original, candidate=original + b'\nNotAProtocolField = invalid\n')
    invoke('apply', operation=invalid['operation'], ok=False)
    assert invoke('status')['operation'] == invalid['operation']
    invoke('rollback-live', operation=invalid['operation'])
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines()) == peers
    print(f'PASS: {container} private journal, operation binding, rollback, commit, replay rejection, native apply and failure rollback; live peers preserved')
