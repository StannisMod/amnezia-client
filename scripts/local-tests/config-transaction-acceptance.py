#!/usr/bin/env python3
"""Exercise the production helper only in the disposable nested Docker daemon."""
import base64
import hashlib
import json
import re
import ipaddress
import subprocess


def run(*args, data=None, ok=True):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if ok and result.returncode:
        raise RuntimeError(f"fixture command failed: {args[0:3]}: {result.stderr.decode(errors='replace')}")
    return result


labels = json.loads(run('docker', 'info', '--format', '{{json .Labels}}').stdout)
assert 'amnezia.test-environment=disposable' in labels, 'requires disposable private Docker daemon'
helper = '/opt/amnezia/config-helper'
feed_image = run('docker', 'inspect', '--format', '{{.Image}}', 'amnezia-connection-updates').stdout.decode().strip()


def feed(action, request):
    result = run('docker', 'run', '--pull=never', '--rm', '-i', '--network', 'none',
                 '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                 '--mount', 'type=volume,source=amnezia-connection-updates-state,target=/data',
                 feed_image, action, data=json.dumps(request).encode())
    return json.loads(result.stdout)

for container, binary, interface, path in (
    ('amnezia-wireguard', 'wg', 'wg0', '/opt/amnezia/wireguard/wg0.conf'),
    ('amnezia-awg2', 'awg', 'awg0', '/opt/amnezia/awg/awg0.conf'),
):
    original = run('docker', 'exec', container, 'cat', path).stdout
    candidate = original + b'\n# private configuration transaction regression\n'
    peers = sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines())

    def invoke(action, operation=None, expected=None, candidate=None, server_ipv6=None, ok=True):
        request = dict(action=action, container=container)
        if operation is not None:
            request['operation'] = operation
        if expected is not None:
            request['expected'] = base64.b64encode(expected).decode()
        if candidate is not None:
            request['candidate'] = base64.b64encode(candidate).decode()
        if server_ipv6 is not None:
            request['serverIpv6'] = server_ipv6
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

    # Construct an old IPv4-only app installation in this disposable namespace.
    # The deliberately unassigned synthetic peer is outside that installation.
    blocks = re.split(rb'(?m)(?=^\[Peer\])', original)
    ipv4_server = b'10.77.0.9/24' if binary == 'wg' else b'10.88.0.9/24'
    header = re.sub(rb'(?m)^Address = [^\n]*', b'Address = ' + ipv4_server, blocks[0])
    legacy_peers = []
    for block in blocks[1:]:
        match = re.search(rb'(?m)^AllowedIPs = ([^\n]+)', block)
        if match is None:
            continue
        ipv4_routes = [route.strip() for route in match[1].split(b',')
                       if ipaddress.ip_network(route.strip().decode(), strict=False).version == 4]
        assert ipv4_routes
        legacy_peers.append(block[:match.start(1)] + b', '.join(ipv4_routes) + block[match.end(1):])
    legacy = header + b''.join(legacy_peers)
    assert len(legacy_peers) >= 2
    setup = invoke('stage', expected=original, candidate=legacy)
    invoke('apply', operation=setup['operation'])
    invoke('commit', operation=setup['operation'])
    if binary == 'awg':
        run('docker', 'exec', container, 'ip', 'address', 'add', ipv4_server.decode(), 'dev', interface)
    target = 'fd77::1/64' if binary == 'wg' else 'fd88::9/64'
    unrelated = 'fd99::9/128'
    run('docker', 'exec', container, 'ip', '-6', 'address', 'del', target, 'dev', interface)
    run('docker', 'exec', container, 'ip', '-6', 'address', 'add', unrelated, 'dev', interface, 'nodad')

    def addresses():
        return run('docker', 'exec', container, 'ip', '-o', '-6', 'address', 'show', 'dev', interface).stdout

    legacy_allowed = allowed()
    legacy_identity = run('docker', 'exec', container, binary, 'show', interface, 'public-key').stdout
    # IPv6 migration must refuse a stale on-disk identity before any live change.
    stale_disk = re.sub(rb'(?m)^PrivateKey = [^\n]*', b'PrivateKey = ' + base64.b64encode(b'Z' * 32), legacy)
    stale = invoke('stage', expected=legacy, candidate=stale_disk)
    invoke('commit', operation=stale['operation'])
    invoke('stage-ipv6', expected=stale_disk, server_ipv6=target, ok=False)
    assert allowed() == legacy_allowed
    assert run('docker', 'exec', container, binary, 'show', interface, 'public-key').stdout == legacy_identity
    assert run('docker', 'exec', container, 'cat', path).stdout == stale_disk
    restore_disk = invoke('stage', expected=stale_disk, candidate=legacy)
    invoke('commit', operation=restore_disk['operation'])

    # Even if the original file is invalid, generic live rollback must restore
    # the actual previous runtime, rather than try parsing that invalid file.
    invalid_disk = legacy + b'\nNotAProtocolField = stale-on-disk-edit\n'
    stale = invoke('stage', expected=legacy, candidate=invalid_disk)
    invoke('commit', operation=stale['operation'])
    changed_runtime = legacy.replace(ipv4, ipv4 + b', ' + added_ipv6, 1)
    repair = invoke('stage', expected=invalid_disk, candidate=changed_runtime)
    invoke('apply', operation=repair['operation'])
    assert allowed() != legacy_allowed
    invoke('rollback-live', operation=repair['operation'])
    assert allowed() == legacy_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == invalid_disk
    restore_disk = invoke('stage', expected=invalid_disk, candidate=legacy)
    invoke('commit', operation=restore_disk['operation'])

    public_key = legacy_identity
    assert run('docker', 'exec', container, binary, 'show', interface, 'public-key').stdout == public_key
    staged_ipv6 = invoke('stage-ipv6', expected=legacy, server_ipv6=target)
    assert len(staged_ipv6['clientIpv6']) == len(legacy_peers)
    assert not staged_ipv6['ipv6AddressPreexisting'] and not staged_ipv6['ipv6Applied']
    invoke('commit', operation=staged_ipv6['operation'], ok=False)
    invoke('rollback', operation=staged_ipv6['operation'], ok=False)
    invoke('rollback-live', operation=staged_ipv6['operation'])
    assert target.encode() not in addresses() and unrelated.encode() in addresses()
    assert allowed() == legacy_allowed

    # Change a real peer's endpoint after snapshotting. Both apply and rollback
    # must preserve the newly learned outer address.
    roaming_key = base64.b64encode(b'B' * 32).decode()
    run('docker', 'exec', container, binary, 'set', interface, 'peer', roaming_key, 'endpoint', '127.0.0.1:29111')
    staged_ipv6 = invoke('stage-ipv6', expected=legacy, server_ipv6=target)
    run('docker', 'exec', container, binary, 'set', interface, 'peer', roaming_key, 'endpoint', '127.0.0.1:29222')
    applied = invoke('apply', operation=staged_ipv6['operation'])
    assert applied['ipv6Applied']
    assert target.encode() in addresses() and unrelated.encode() in addresses()
    actual_routes = dict(allowed())
    for key, address in staged_ipv6['clientIpv6'].items():
        assert (address + '/128').encode() in actual_routes[key.encode()]
    recovered_status = invoke('status')
    assert recovered_status['clientIpv6'] == staged_ipv6['clientIpv6']
    # Exercise the production admin executable and persisted receipt, not a mock.
    # This lab has no active client sessions using the newly published addresses.
    feed_info = feed('info', {})
    feed('issue', dict(container=container, clientPublicKey=roaming_key,
                        settings=dict(hostName=feed_info['host'],
                                      port=int(run('docker', 'exec', container, binary, 'show', interface, 'listen-port').stdout),
                                      server_pub_key=public_key.decode().strip())))
    publication = dict(container=container, operation=staged_ipv6['operation'],
                       expectedState=feed('info', {})['stateTag'],
                       clientIpv6=staged_ipv6['clientIpv6'])
    feed('publish-ipv6-if', publication)  # Discard reply, as if SSH was interrupted.
    receipt = feed('ipv6-publication-status', dict(container=container, operation=publication['operation']))
    assert receipt['known'] and receipt['current']
    published_tag = receipt['stateTag']
    replay = feed('publish-ipv6-if', publication)
    assert replay['replayed'] and replay['operation'] == publication['operation']
    assert feed('info', {})['stateTag'] == published_tag, 'retry changed revisions'
    # Explicit withdrawal advances revisions rather than reverting a state file.
    withdrawal = dict(container=container,
                      operation=hashlib.sha256((publication['operation'] + 'withdraw').encode()).hexdigest(),
                      expectedState=published_tag,
                      clientIpv6={key: '' for key in publication['clientIpv6']})
    feed('publish-ipv6-if', withdrawal)
    assert feed('info', {})['stateTag'] != published_tag
    invoke('rollback-live', operation=staged_ipv6['operation'])
    assert target.encode() not in addresses() and unrelated.encode() in addresses()
    assert allowed() == legacy_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == legacy
    assert run('docker', 'exec', container, binary, 'show', interface, 'public-key').stdout == public_key
    endpoints = dict(line.split(b'\t', 1) for line in run('docker', 'exec', container, binary, 'show', interface, 'endpoints').stdout.splitlines())
    assert endpoints[roaming_key.encode()] == b'127.0.0.1:29222', 'rollback reset an authenticated roaming endpoint'

    # A preexisting address must survive the same apply/rollback sequence.
    run('docker', 'exec', container, 'ip', '-6', 'address', 'add', target, 'dev', interface, 'nodad')
    existing = invoke('stage-ipv6', expected=legacy, server_ipv6=target)
    assert existing['ipv6AddressPreexisting']
    invoke('apply', operation=existing['operation'])
    invoke('rollback-live', operation=existing['operation'])
    assert target.encode() in addresses() and unrelated.encode() in addresses()
    restore = invoke('stage', expected=legacy, candidate=original)
    invoke('apply', operation=restore['operation'])
    invoke('commit', operation=restore['operation'])
    run('docker', 'exec', container, 'ip', '-6', 'address', 'del', unrelated, 'dev', interface)
    if binary == 'awg':
        run('docker', 'exec', container, 'ip', 'address', 'del', ipv4_server.decode(), 'dev', interface)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines()) == peers
    print(f'PASS: {container} legacy migration, native snapshot rollback, stale identity rejection, roaming preservation and IPv6 address ownership')
