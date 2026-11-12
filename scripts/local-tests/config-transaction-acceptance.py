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


def native_fields(raw):
    # AWG's UAPI iterates peers in map order. Preserve every field/value and
    # duplicate while ignoring only peer/field order and blank formatting.
    return tuple(sorted(tuple(sorted(line.strip() for line in block.splitlines() if line.strip()))
                        for block in raw.split(b'[Peer]')))


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

    def invoke(action, operation=None, expected=None, candidate=None, server_ipv6=None, ok=True, startup=False, no_writer=False, after_writer=False, entry=None):
        request = dict(action=action, container=container)
        if operation is not None:
            request['operation'] = operation
        if expected is not None:
            request['expected'] = base64.b64encode(expected).decode()
        if candidate is not None:
            request['candidate'] = base64.b64encode(candidate).decode()
        if server_ipv6 is not None:
            request['serverIpv6'] = server_ipv6
        if entry is not None:
            request['expectedEntry'] = entry
        command = ['docker', 'exec']
        if no_writer or after_writer:
            folder = 'no-writer' if no_writer else 'after-writer'
            command += ['-e', 'PATH=/opt/amnezia/' + folder + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
        result = run(*command, '-i', container, helper,
                     'startup-file-transaction' if startup else 'config-file-transaction',
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
    # Model process interruption immediately before and after the native command.
    # Journal edits are confined to this labelled disposable daemon; all native
    # state changes still use the actual production helper and protocol stack.
    tool_path = run('docker', 'exec', container, 'sh', '-c', 'command -v ' + binary).stdout.decode().strip()
    assert tool_path.startswith('/') and all(c.isalnum() or c in '/_-' for c in tool_path)
    run('docker', 'exec', container, 'mkdir', '-p', '/opt/amnezia/no-writer')
    block_writer = ('#!/bin/sh\nif [ "$1" = syncconf ]; then touch /opt/amnezia/forbidden-recovery-writer; exit 89; fi\n'
                    'exec ' + tool_path + ' "$@"\n').encode()
    run('docker', 'exec', '-i', container, 'sh', '-ec',
        'umask 077; cat > /opt/amnezia/no-writer/' + binary + '; chmod 700 /opt/amnezia/no-writer/' + binary,
        data=block_writer)

    def interrupted_flags():
        edit = "import json,pathlib; p=pathlib.Path(" + repr(path + '.amnezia-journal') + "); j=json.loads(p.read_bytes()); j['nativeWriteIntent']=True; j['nativeApplied']=False; p.write_text(json.dumps(j))"
        run('docker', 'exec', container, 'python3', '-c', edit)

    def restore_baseline():
        pending = invoke('stage-live', expected=live_candidate, candidate=original)
        invoke('apply-commit', operation=pending['operation'])
        assert allowed() == original_allowed

    before_write = invoke('stage-live', expected=original, candidate=live_candidate)
    interrupted_flags()
    invoke('apply-commit', operation=before_write['operation'])
    assert allowed() != original_allowed
    restore_baseline()
    after_write = invoke('stage-live', expected=original, candidate=live_candidate)
    invoke('apply', operation=after_write['operation'])
    applied_routes = allowed()
    interrupted_flags()
    invoke('apply-commit', operation=after_write['operation'], no_writer=True)
    assert allowed() == applied_routes
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    restore_baseline()
    conflict = invoke('stage-live', expected=original, candidate=live_candidate)
    interrupted_flags()
    recovery_peer = base64.b64encode(b'B' * 32).decode()
    recovery_routes = dict(original_allowed)[recovery_peer.encode()]
    run('docker', 'exec', container, binary, 'set', interface, 'peer', recovery_peer,
        'allowed-ips', ','.join(route.decode() for route in recovery_routes) + ',fd99::55/128')
    foreign_routes = allowed()
    invoke('apply-commit', operation=conflict['operation'], ok=False, no_writer=True)
    assert allowed() == foreign_routes
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    assert run('docker', 'exec', container, 'cat', path).stdout == live_candidate
    run('docker', 'exec', container, binary, 'set', interface, 'peer', recovery_peer,
        'allowed-ips', ','.join(route.decode() for route in recovery_routes))
    invoke('apply-commit', operation=conflict['operation'])
    restore_baseline()

    # Rollback must inspect native ownership BEFORE changing the file. A saved
    # canonical candidate digest remains usable after a failed rollback has
    # already replaced that file with the original (possibly invalid) bytes.
    rollback_stage = invoke('stage-live', expected=original, candidate=live_candidate)
    invoke('apply', operation=rollback_stage['operation'])
    rollback_candidate_routes = dict(allowed())[recovery_peer.encode()]
    run('docker', 'exec', container, binary, 'set', interface, 'peer', recovery_peer,
        'allowed-ips', ','.join(route.decode() for route in rollback_candidate_routes) + ',fd99::55/128')
    rollback_foreign = allowed()
    journal_before = run('docker', 'exec', container, 'cat', path + '.amnezia-journal').stdout
    invoke('rollback-live', operation=rollback_stage['operation'], ok=False, no_writer=True)
    assert allowed() == rollback_foreign
    assert run('docker', 'exec', container, 'cat', path).stdout == live_candidate
    assert run('docker', 'exec', container, 'cat', path + '.amnezia-journal').stdout == journal_before
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    run('docker', 'exec', container, binary, 'set', interface, 'peer', recovery_peer,
        'allowed-ips', ','.join(route.decode() for route in rollback_candidate_routes))
    invoke('rollback-live', operation=rollback_stage['operation'], ok=False, no_writer=True)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    rollback_receipt = json.loads(run('docker', 'exec', container, 'cat', path + '.amnezia-journal').stdout)
    assert rollback_receipt['version'] == 6 and len(rollback_receipt['nativeRollbackHash']) == 64
    assert invoke('status')['rollbackPending']
    assert not run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer').returncode
    run('docker', 'exec', container, 'rm', '/opt/amnezia/forbidden-recovery-writer')
    invoke('apply', operation=rollback_stage['operation'], ok=False)
    invoke('apply-commit', operation=rollback_stage['operation'], ok=False)
    invoke('commit', operation=rollback_stage['operation'], ok=False)
    run('docker', 'exec', container, binary, 'set', interface, 'peer', recovery_peer,
        'allowed-ips', ','.join(route.decode() for route in rollback_candidate_routes) + ',fd99::55/128')
    rollback_foreign = allowed()
    invoke('rollback-live', operation=rollback_stage['operation'], ok=False, no_writer=True)
    assert allowed() == rollback_foreign
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    run('docker', 'exec', container, binary, 'set', interface, 'peer', recovery_peer,
        'allowed-ips', ','.join(route.decode() for route in rollback_candidate_routes))
    invoke('rollback-live', operation=rollback_stage['operation'])
    assert allowed() == original_allowed

    run('docker', 'exec', container, 'mkdir', '-p', '/opt/amnezia/after-writer')
    applied_then_lost = ('#!/bin/sh\nif [ "$1" = syncconf ]; then ' + tool_path + ' "$@" || exit $?; '
                         'touch /opt/amnezia/rollback-writer-applied; exit 89; fi\nexec ' + tool_path + ' "$@"\n').encode()
    run('docker', 'exec', '-i', container, 'sh', '-ec',
        'umask 077; cat > /opt/amnezia/after-writer/' + binary + '; chmod 700 /opt/amnezia/after-writer/' + binary,
        data=applied_then_lost)
    restored_then_lost = invoke('stage-live', expected=original, candidate=live_candidate)
    invoke('apply', operation=restored_then_lost['operation'])
    invoke('rollback-live', operation=restored_then_lost['operation'], ok=False, after_writer=True)
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert not run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/rollback-writer-applied').returncode
    completed_rollback = invoke('rollback-live', operation=restored_then_lost['operation'], no_writer=True)
    assert not completed_rollback['rollbackPending']
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode

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
    # Strict normal peer mutation: reject concurrent native edits both before
    # application and after a successful apply, without overwriting those edits.
    peer_key = base64.b64encode(b'B' * 32).decode()
    routes_before = dict(original_allowed)[peer_key.encode()]
    invoke('stage-live', expected=original,
           candidate=original.replace(b'Address = ', b'Address = fd66::1/64, ', 1), ok=False)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert allowed() == original_allowed
    pending_live = invoke('stage-live', expected=original, candidate=live_candidate)
    run('docker', 'exec', container, binary, 'set', interface, 'peer', peer_key,
        'allowed-ips', ','.join(route.decode() for route in routes_before) + ',fd99::55/128')
    independently_changed = allowed()
    invoke('apply-commit', operation=pending_live['operation'], ok=False)
    assert allowed() == independently_changed
    invoke('rollback-live', operation=pending_live['operation'])
    assert allowed() == independently_changed
    run('docker', 'exec', container, binary, 'set', interface, 'peer', peer_key,
        'allowed-ips', ','.join(route.decode() for route in routes_before))
    assert allowed() == original_allowed
    pending_live = invoke('stage-live', expected=original, candidate=live_candidate)
    invoke('apply', operation=pending_live['operation'])
    applied_routes = allowed()
    peer_routes = dict(applied_routes)[peer_key.encode()]
    run('docker', 'exec', container, binary, 'set', interface, 'peer', peer_key,
        'allowed-ips', ','.join(route.decode() for route in peer_routes) + ',fd99::55/128')
    independently_changed = allowed()
    invoke('commit', operation=pending_live['operation'], ok=False)
    invoke('apply-commit', operation=pending_live['operation'], ok=False)
    invoke('apply', operation=pending_live['operation'], ok=False, no_writer=True)
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    assert allowed() == independently_changed
    invoke('check-live', expected=live_candidate, ok=False)
    assert allowed() == independently_changed
    assert invoke('status')['operation'] == pending_live['operation']
    run('docker', 'exec', container, binary, 'set', interface, 'peer', peer_key,
        'allowed-ips', ','.join(route.decode() for route in peer_routes))
    invoke('commit', operation=pending_live['operation'])
    restore_live = invoke('stage-live', expected=live_candidate, candidate=original)
    invoke('apply-commit', operation='0' * 64, ok=False)
    invoke('apply-commit', operation=restore_live['operation'])
    invoke('status', ok=False)
    assert invoke('check-live', expected=original)['current']
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    # The native parser really rejects this candidate; the durable journal survives.
    invalid = invoke('stage', expected=original, candidate=original + b'\nNotAProtocolField = invalid\n')
    invoke('apply-commit', operation=invalid['operation'], ok=False)
    assert invoke('status')['operation'] == invalid['operation']
    invoke('rollback-live', operation=invalid['operation'])
    assert allowed() == original_allowed
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines()) == peers
    # An opted-in receipt survives later cooperating edits without replaying an
    # old full config. Only absence of the exact revoked key can be confirmed.
    receipt_id = hashlib.sha256((container + '-receipt-removal').encode()).hexdigest()
    receipt_blocks = re.split(rb'(?m)(?=^\[Peer\])', original)
    removed_blocks = [block for block in receipt_blocks[1:]
                      if re.search(rb'(?m)^PublicKey = ' + re.escape(peer_key.encode()) + rb'\s*$', block)]
    assert len(removed_blocks) == 1
    removed_config = b''.join(block for block in receipt_blocks if block not in removed_blocks)
    prepared = invoke('prepare-receipt', operation=receipt_id, expected=original, candidate=removed_config)
    assert prepared['state'] == 'pending'
    assert invoke('prepare-receipt', operation=receipt_id, expected=original, candidate=removed_config)['state'] == 'pending'
    invoke('prepare-receipt', operation=receipt_id, expected=original, candidate=removed_config + b'\n# wrong context\n', ok=False)
    invoke('ack-receipt', operation=receipt_id, expected=original, candidate=removed_config, ok=False)
    invoke('check-revoked-peer', operation=receipt_id, expected=original, candidate=removed_config, ok=False, no_writer=True)
    removal = invoke('stage-live', expected=original, candidate=removed_config)
    invoke('apply-commit', operation=removal['operation'])
    terminal = invoke('receipt-status', operation=receipt_id, expected=original, candidate=removed_config)
    assert terminal['state'] == 'committed' and terminal['nativeOperation'] == removal['operation']
    check = invoke('check-revoked-peer', operation=receipt_id, expected=original, candidate=removed_config, no_writer=True)
    assert check['revoked'] and check['clientPublicKey'] == peer_key
    # Change a remaining peer through a separate real native transaction.
    independent = re.split(rb'(?m)(?=^\[Peer\])', removed_config)
    assert len(independent) > 1
    independent[1] = re.sub(rb'(?m)^PersistentKeepalive = [^\n]*\n?', b'', independent[1]).rstrip(b'\n') + b'\nPersistentKeepalive = 17\n'
    assert b'PresharedKey =' not in independent[1], 'fixture peer must start without a PSK'
    independent[1] += b'PresharedKey = ' + base64.b64encode(b'Z' * 32) + b'\n'
    independent_config = b''.join(independent)
    separate = invoke('stage-live', expected=removed_config, candidate=independent_config)
    invoke('apply-commit', operation=separate['operation'])
    independent_native = run('docker', 'exec', container, binary, 'showconf', interface).stdout
    invoke('check-live', expected=removed_config, ok=False)
    check = invoke('check-revoked-peer', operation=receipt_id, expected=original, candidate=removed_config, no_writer=True)
    assert check['revoked']
    assert run('docker', 'exec', container, 'cat', path).stdout == independent_config
    after_check_native = run('docker', 'exec', container, binary, 'showconf', interface).stdout
    assert native_fields(after_check_native) == native_fields(independent_native), 'receipt check changed native fields'
    if after_check_native != independent_native:
        print(f'PASS: {container} native fields unchanged despite different peer serialization order')
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    # Historical completion is not permission to delete a reintroduced peer.
    restoration = invoke('stage-live', expected=independent_config, candidate=original)
    invoke('apply-commit', operation=restoration['operation'])
    invoke('check-revoked-peer', operation=receipt_id, expected=original, candidate=removed_config, ok=False, no_writer=True)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert invoke('ack-receipt', operation=receipt_id, expected=original, candidate=removed_config)['acknowledged']
    assert invoke('ack-receipt', operation=receipt_id, expected=original, candidate=removed_config)['acknowledged']
    invoke('receipt-status', operation=receipt_id, expected=original, candidate=removed_config, ok=False)
    # A live rollback must replace a prior terminal/intent with rollback outcome.
    rollback_receipt = hashlib.sha256((container + '-receipt-rollback').encode()).hexdigest()
    invoke('prepare-receipt', operation=rollback_receipt, expected=original, candidate=removed_config)
    removal = invoke('stage-live', expected=original, candidate=removed_config)
    invoke('apply', operation=removal['operation'])
    invoke('rollback-live', operation=removal['operation'])
    assert invoke('receipt-status', operation=rollback_receipt, expected=original, candidate=removed_config)['state'] == 'rolled-back'
    invoke('check-revoked-peer', operation=rollback_receipt, expected=original, candidate=removed_config, ok=False, no_writer=True)
    invoke('ack-receipt', operation=rollback_receipt, expected=original, candidate=removed_config)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines()) == peers
    print(f'PASS: {container} durable terminal receipts preserve later native edits, reject reintroduced peers and retain rollback direction')
    # Metadata intents reserve one public key, never the whole client table.
    table_path = path.rsplit('/', 1)[0] + '/clientsTable'
    old_table = run('docker', 'exec', container, 'cat', table_path).stdout
    target_entry = dict(clientId=peer_key, userData=dict(clientName='reserved', n=1000))
    other_entry = dict(clientId='other metadata', userData=dict(clientName='editable'))
    def write_fixture_table(raw):
        run('docker', 'exec', '-i', container, 'sh', '-ec', 'cat > ' + table_path, data=raw)
    reserved_table = json.dumps([target_entry, other_entry]).encode().replace(b'"n": 1000', b'"n": 1e3')
    write_fixture_table(reserved_table)
    intent_id = hashlib.sha256((container + '-metadata-intent').encode()).hexdigest()
    prepared = invoke('prepare-peer-metadata', operation=intent_id, expected=original, candidate=removed_config, entry=target_entry)
    assert prepared['targetKey'] == peer_key and len(prepared['targetMetadataHash']) == 64
    receipt_bytes = run('docker', 'exec', container, 'cat', path + '.amnezia-receipts').stdout
    store = json.loads(receipt_bytes)
    assert store['version'] == 2 and store['records'][intent_id]['targetKey'] == peer_key
    assert b'reserved' not in receipt_bytes, 'receipt copied private metadata instead of its digest'
    invoke('prepare-peer-metadata', operation='f' * 64, expected=original, candidate=removed_config, entry=target_entry, ok=False)
    assert run('docker', 'exec', container, 'cat', path + '.amnezia-receipts').stdout == receipt_bytes
    wrong_entry = dict(target_entry, userData=dict(clientName='wrong'))
    invoke('prepare-peer-metadata', operation=intent_id, expected=original, candidate=removed_config, entry=wrong_entry, ok=False)
    renamed = json.dumps([dict(target_entry, userData=dict(clientName='forbidden')), other_entry]).encode()
    invoke('replace-client-table', expected=reserved_table, candidate=renamed, ok=False)
    assert run('docker', 'exec', container, 'cat', table_path).stdout == reserved_table
    changed_other = dict(other_entry, userData=dict(clientName='changed independently', extra=True))
    changed_table = json.dumps([target_entry, changed_other]).encode()
    invoke('replace-client-table', expected=reserved_table, candidate=changed_table)
    removed_table = json.dumps([changed_other]).encode()
    invoke('replace-client-table', operation=intent_id, expected=changed_table, candidate=removed_table, ok=False)
    removal = invoke('stage-live', expected=original, candidate=removed_config)
    invoke('apply-commit', operation=removal['operation'])
    assert invoke('check-revoked-peer', operation=intent_id, expected=original, candidate=removed_config, no_writer=True)['revoked']
    reintroduced = invoke('stage-live', expected=removed_config, candidate=original)
    invoke('apply-commit', operation=reintroduced['operation'])
    invoke('replace-client-table', operation=intent_id, expected=changed_table, candidate=removed_table, ok=False, no_writer=True)
    assert run('docker', 'exec', container, 'cat', table_path).stdout == changed_table
    removed_again = invoke('stage-live', expected=original, candidate=removed_config)
    invoke('apply-commit', operation=removed_again['operation'])
    # Independently changed target metadata is preserved even from its owner.
    write_fixture_table(renamed)
    invoke('replace-client-table', operation=intent_id, expected=renamed, candidate=removed_table, ok=False, no_writer=True)
    assert run('docker', 'exec', container, 'cat', table_path).stdout == renamed
    write_fixture_table(changed_table)  # Restore only the fixture's injected edit.
    invoke('replace-client-table', operation=intent_id, expected=changed_table, candidate=removed_table, no_writer=True)
    assert run('docker', 'exec', container, 'cat', table_path).stdout == removed_table
    invoke('replace-client-table', expected=removed_table, candidate=changed_table, ok=False)
    invoke('replace-client-table', operation=intent_id, expected=removed_table, candidate=changed_table, ok=False)
    assert invoke('ack-receipt', operation=intent_id, expected=original, candidate=removed_config)['acknowledged']
    invoke('replace-client-table', expected=removed_table, candidate=changed_table)
    restoration = invoke('stage-live', expected=removed_config, candidate=original)
    invoke('apply-commit', operation=restoration['operation'])
    write_fixture_table(old_table)
    assert run('docker', 'exec', container, 'cat', path).stdout == original
    assert sorted(run('docker', 'exec', container, binary, 'show', interface, 'peers').stdout.splitlines()) == peers
    print(f'PASS: {container} peer metadata intent preserves other clients and requires committed owner removal')
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
    invoke('prepare-forwarding', operation=staged_ipv6['operation'], ok=False)
    invoke('rollback', operation=staged_ipv6['operation'], ok=False)
    invoke('rollback-live', operation=staged_ipv6['operation'])
    assert target.encode() not in addresses() and unrelated.encode() in addresses()
    assert allowed() == legacy_allowed

    # A separate administrator changes native routes after staging, without
    # changing the file. Reject before IPv6 activation, and preserve that edit
    # when rolling back a transaction that never attempted a protocol write.
    changed_key = base64.b64encode(b'B' * 32).decode()
    original_peer_routes = dict(legacy_allowed)[changed_key.encode()]
    concurrent_route = 'fd99::b/128'
    concurrent = invoke('stage-ipv6', expected=legacy, server_ipv6=target)
    run('docker', 'exec', container, binary, 'set', interface, 'peer', changed_key,
        'allowed-ips', ','.join(route.decode() for route in original_peer_routes) + ',' + concurrent_route)
    independently_changed = allowed()
    invoke('apply', operation=concurrent['operation'], ok=False)
    assert target.encode() not in addresses(), 'conflicting migration activated IPv6'
    assert allowed() == independently_changed, 'conflicting apply overwrote native edit'
    invoke('rollback-live', operation=concurrent['operation'])
    assert allowed() == independently_changed, 'unapplied rollback overwrote native edit'
    assert run('docker', 'exec', container, 'cat', path).stdout == legacy
    run('docker', 'exec', container, binary, 'set', interface, 'peer', changed_key,
        'allowed-ips', ','.join(route.decode() for route in original_peer_routes))
    assert allowed() == legacy_allowed

    # Change a real peer's endpoint after snapshotting. Both apply and rollback
    # must preserve the newly learned outer address.
    roaming_key = base64.b64encode(b'B' * 32).decode()
    run('docker', 'exec', container, binary, 'set', interface, 'peer', roaming_key, 'endpoint', '127.0.0.1:29111')
    staged_ipv6 = invoke('stage-ipv6', expected=legacy, server_ipv6=target)
    run('docker', 'exec', container, binary, 'set', interface, 'peer', roaming_key, 'endpoint', '127.0.0.1:29222')
    applied = invoke('apply', operation=staged_ipv6['operation'])
    assert applied['ipv6Applied']
    interrupted_ipv6 = "import json,pathlib; p=pathlib.Path(" + repr(path + '.amnezia-journal') + "); j=json.loads(p.read_bytes()); j['nativeApplied']=False; j['ipv6']['applied']=False; p.write_text(json.dumps(j))"
    run('docker', 'exec', container, 'python3', '-c', interrupted_ipv6)
    run('docker', 'exec', container, 'ip', '-6', 'addr', 'del', target, 'dev', interface)
    invoke('apply', operation=staged_ipv6['operation'], ok=False, no_writer=True)
    assert target.encode() not in addresses(), 'recovery recreated independently removed IPv6 address'
    assert unrelated.encode() in addresses()
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    run('docker', 'exec', container, 'ip', '-6', 'addr', 'add', target, 'dev', interface, 'nodad')
    applied = invoke('apply', operation=staged_ipv6['operation'], no_writer=True)
    assert applied['ipv6Applied'] and applied['nativeApplied']
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-recovery-writer', ok=False).returncode
    invoke('prepare-forwarding', operation='0' * 64, ok=False)
    startup = run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout
    old_startup = b'#!/bin/bash\ntouch /opt/amnezia/forbidden-startup-body\nexit 87\n'
    run('docker', 'exec', '-i', container, 'sh', '-ec', 'cat > /opt/amnezia/start.sh', data=old_startup)
    invoke('prepare-forwarding', operation=staged_ipv6['operation'], ok=False)
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-startup-body', ok=False).returncode != 0
    upgrade = invoke('stage', expected=old_startup, candidate=startup, startup=True)
    recovered_upgrade = invoke('status', startup=True)
    assert recovered_upgrade['operation'] == upgrade['operation']
    invoke('rollback', operation='0' * 64, startup=True, ok=False)
    invoke('rollback', operation=upgrade['operation'], startup=True)
    assert run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout == old_startup
    upgrade = invoke('stage', expected=old_startup, candidate=startup, startup=True)
    invoke('commit', operation=upgrade['operation'], startup=True)
    assert run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout == startup
    assert run('docker', 'exec', container, 'stat', '-c', '%a', '/opt/amnezia/start.sh').stdout.strip() == b'700'
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-startup-body', ok=False).returncode != 0
    legacy_block = run('docker', 'exec', container, 'cat', '/opt/amnezia/fixture-forwarding-legacy.sh').stdout + b'\n'
    historical_startup = b'#!/bin/bash\n' + legacy_block + old_startup.split(b'\n', 1)[1]
    run('docker', 'exec', '-i', container, 'sh', '-ec', 'cat > /opt/amnezia/start.sh', data=historical_startup)
    historical_upgrade = invoke('stage', expected=historical_startup, candidate=startup, startup=True)
    invoke('rollback', operation=historical_upgrade['operation'], startup=True)
    assert run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout == historical_startup
    historical_upgrade = invoke('stage', expected=historical_startup, candidate=startup, startup=True)
    invoke('commit', operation=historical_upgrade['operation'], startup=True)
    assert run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout == startup
    # Upgrade the real known startup body as well as the maintenance capability.
    template = run('docker', 'exec', container, 'cat', '/opt/amnezia/fixture-startup-source.sh').stdout.replace(b'$SERVER_IP_ADDRESS', b'203.0.113.7')
    boot_call = ("\namnezia_enable_ipv6 " + interface + " || echo 'AMNEZIA_IPV6_FORWARDING_STATUS=boot-preparation-failed' >&2\n").encode()
    assert template.count(boot_call) == 1
    old_template = template.replace(boot_call, b'', 1)
    verified_prefix = startup[:startup.index(b'\ntouch /opt/amnezia/forbidden-startup-body') + 1]
    boot_candidate = verified_prefix + template.split(b'\n', 1)[1]
    run('docker', 'exec', '-i', container, 'sh', '-ec', 'cat > /opt/amnezia/start.sh', data=old_template)
    boot_upgrade = invoke('stage', expected=old_template, candidate=boot_candidate, startup=True)
    assert run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout == boot_candidate
    invoke('rollback', operation=boot_upgrade['operation'], startup=True)
    assert run('docker', 'exec', container, 'cat', '/opt/amnezia/start.sh').stdout == old_template
    # Restore the dedicated non-executing fixture; no tunnel restart is performed.
    run('docker', 'exec', '-i', container, 'sh', '-ec', 'cat > /opt/amnezia/start.sh', data=startup)
    # No IPv6 default route yet: preparation must fail, retaining the journal.
    invoke('prepare-forwarding', operation=staged_ipv6['operation'], ok=False)
    run('docker', 'exec', container, 'ip', 'link', 'add', 'v6fixture0', 'type', 'dummy')
    run('docker', 'exec', container, 'ip', 'link', 'set', 'v6fixture0', 'up')
    run('docker', 'exec', container, 'ip', '-6', 'addr', 'add', 'fd98::2/64', 'dev', 'v6fixture0', 'nodad')
    run('docker', 'exec', container, 'ip', '-6', 'route', 'add', 'default', 'dev', 'v6fixture0')
    try:
        prepared_forwarding = invoke('prepare-forwarding', operation=staged_ipv6['operation'])
    except RuntimeError as error:
        # Only the known synthetic fixture prefix contains no configuration keys.
        prefix = startup[:startup.index(b'\ntouch /opt/amnezia/forbidden-startup-body') + 1]
        diagnostic = run('docker', 'exec', '-i', container, 'env', '-i',
                         'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
                         '/bin/bash', '-x', '-s', '--', '--amnezia-prepare-ipv6-forwarding', interface,
                         data=prefix, ok=False)
        raise RuntimeError('known forwarding prefix diagnostic: ' + diagnostic.stderr.decode(errors='replace')) from error
    assert prepared_forwarding['ipv6ForwardingPrepared']
    rules = run('docker', 'exec', container, 'ip6tables-save').stdout
    assert invoke('prepare-forwarding', operation=staged_ipv6['operation'])['ipv6ForwardingPrepared']
    # iptables-save includes changing timestamps; compare rule lines only.
    after_rules = run('docker', 'exec', container, 'ip6tables-save').stdout
    assert [line for line in rules.splitlines() if not line.startswith(b'#')] == [line for line in after_rules.splitlines() if not line.startswith(b'#')]
    assert run('docker', 'exec', container, 'test', '-e', '/opt/amnezia/forbidden-startup-body', ok=False).returncode != 0
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
