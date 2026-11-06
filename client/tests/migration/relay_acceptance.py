#!/usr/bin/env python3
"""Real new-host pull with old SSH blocked to the administrator's network."""
import hashlib
import json
from pathlib import Path
import subprocess
import time
import tempfile
import uuid
import scenario_acceptance as fixture

host, d, cmd = fixture.host, fixture.d, fixture.cmd
OP = fixture.OP
ADDRESS = {}
SOURCE_CREDENTIALS = {}
SOURCE_IDENTITY = {}


def relay(action, expect=True, authorize=True, **params):
    req = {'operation': OP, 'action': action, **params}
    if authorize:
        req.update({'source': SOURCE_CREDENTIALS, 'sourceIdentity': SOURCE_IDENTITY})
    private = '/tmp/amnezia-migration-'+OP+'/request-'+uuid.uuid4().hex+'.json'
    fixture.copy('target', json.dumps(req), private)
    result = cmd('docker', 'exec', '-i', fixture.HOSTS['target'], 'python3',
                 '/tmp/amnezia-migration-'+OP+'/relay.py', private, check=False)
    host('target', 'test', '!', '-e', private)
    reply = json.loads(result.stdout)
    assert bool(reply.get('ok')) == expect, {k:v for k,v in reply.items() if k not in ('identity', 'source')}
    return reply


def local(action, expect=True, **params):
    return fixture.agent('target', action, expect=expect, **params)


def source(action, **params):
    return relay('source-command', command=action, **params)


def interrupt_after_first_stop(side, action):
    # Test-only fault injection, no production failure switches. A real Docker
    # container is stopped, then the invoking process disappears before completion.
    script = """import sys
sys.path.insert(0,'/tmp/amnezia-migration-'+sys.argv[1])
import agent
real=agent.run
def interrupted(*args,**kwargs):
 result=real(*args,**kwargs)
 if args[0]=='stop': raise SystemExit(73)
 return result
agent.run=interrupted
agent.main({'operation':sys.argv[1],'action':sys.argv[2]})
"""
    r = cmd('docker', 'exec', '-i', fixture.HOSTS[side], 'python3', '-c', script, OP, action, check=False)
    assert r.returncode == 73


def interrupt_rollback_after_source_start():
    # Inject the interruption through the new host's real SSH connection, after
    # store import and the first successful source start. No production test hook.
    request = {'operation':OP, 'action':'rollback', 'source':SOURCE_CREDENTIALS, 'sourceIdentity':SOURCE_IDENTITY}
    script = r"""import json,shlex,sys
request=json.load(sys.stdin)
sys.path.insert(0,'/tmp/amnezia-migration-'+request['operation'])
import relay
real=relay.Source.call
def interrupted(self,action,**params):
 if action=='abort':
  remote="import sys; sys.path.insert(0,"+repr(self.stage)+"); import agent\nreal=agent.run\ndef run(*args,**kwargs):\n result=real(*args,**kwargs)\n if args[0]=='start': raise SystemExit(73)\n return result\nagent.run=run\nagent.main({'operation':"+repr(self.work.name)+",'action':'abort'})"
  return self.command(relay.privileged('python3 -B -c '+shlex.quote(remote)))
 return real(self,action,**params)
relay.Source.call=interrupted
reply=relay.respond(request)
assert not reply['ok']
"""
    host('target', 'python3', '-c', script, data=json.dumps(request))


def exercise_application_admin_commands(info, settings):
    # Execute the actual C++ command builder used by ConnectionUpdatesController
    # through real pinned SSH, with no amnezia-connection-updates:1 tag present.
    assert not d('target', 'images', '-q', 'amnezia-connection-updates:1').strip()
    host('target', 'mkdir', '-p', '/root/.ssh', '/run/sshd')
    fixture.copy('target', host('target', 'cat', '/tmp/source-identity.pub'), '/root/.ssh/authorized_keys')
    host('target', 'chpasswd', data='root:synthetic-target-password-'+OP+'\n')
    host('target', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/tmp/target-hostkey')
    config = 'Port 2223\nListenAddress 0.0.0.0\nHostKey /tmp/target-hostkey\nPermitRootLogin yes\nPasswordAuthentication no\nUsePAM no\nPidFile /tmp/target-sshd.pid\nSubsystem sftp internal-sftp\n'
    fixture.copy('target', config, '/tmp/target-sshd_config')
    cmd('docker', 'exec', '-d', fixture.HOSTS['target'], '/usr/sbin/sshd', '-D', '-f', '/tmp/target-sshd_config')
    fields = host('target', 'cat', '/tmp/target-hostkey.pub').split()
    import base64
    fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(fields[1])).digest()).decode().rstrip('=')
    with tempfile.TemporaryDirectory(prefix='amnezia-admin-fixture-') as temp:
        request = Path(temp)/'admin.json'
        request.write_text(json.dumps({'host':ADDRESS['target'], 'port':2223, 'fingerprint':fingerprint,
                                       'key':SOURCE_CREDENTIALS['secret'], 'settings':settings,
                                       'publicKey':info['publicKey'], 'certificate':info['certificate']}))
        request.chmod(0o600)
        cmd('docker', 'run', '--rm', '--network', fixture.NETWORK,
            '--mount', 'type=bind,source='+str(fixture.REPO)+',target=/src,readonly',
            '--mount', 'type=bind,source='+temp+',target=/fixture,readonly',
            'amnezia-migration-ssh-tests', 'sh', '-ec',
            'cmake -S /src/client/tests/migration -B /tmp/migration-tests -G Ninja >/dev/null; '
            'cmake --build /tmp/migration-tests -j 4 >/dev/null; '
            '/tmp/migration-tests/migration_ssh_harness admin /fixture/admin.json')


def exercise_migrated_host_as_rollback_source():
    # A migrated host may be the source of the next move. Exercise the real
    # source export/stop/store-import/restart on its actual migrated volume.
    script = r"""import hashlib,json,os,sys,uuid
from pathlib import Path
os.umask(0o077)
sys.path.insert(0,'/tmp/amnezia-migration-'+sys.argv[1])
import agent
operation=uuid.uuid4().hex
call=lambda action,**extra: agent.main({'operation':operation,'action':action,**extra})
volume=agent.inspect('volume',agent.VOLUME)
assert volume['Labels']['org.amnezia.connection-updates']=='1'
assert agent.LABEL in volume['Labels']
call('export')
work=agent.ROOT/operation
manifest=json.loads((work/'journal.json').read_bytes())['manifest']
call('source-stop')
helper=next(manifest['images'][c['Name'][1:]] for c in manifest['containers'] if agent.SPECS[c['Name'][1:]])
raw=agent.volume_tar(helper,agent.VOLUME)
stage=agent.client_stage(operation); stage.mkdir(mode=0o700)
(stage/'rollback.tar').write_bytes(raw)
call('rollback-import',sha256=hashlib.sha256(raw).hexdigest())
call('abort')
assert all(call('status')['running'].values())
call('finalize')
(stage/'rollback.tar').unlink(); stage.rmdir()
print('PASS: migrated host accepts a later rollback into its delivery volume')
"""
    print(host('target', 'python3', '-B', '-c', script, OP).strip(), flush=True)


def main():
    global ADDRESS, SOURCE_CREDENTIALS, SOURCE_IDENTITY
    fixture.setup()
    clients, info, issued = fixture.fixture()
    ADDRESS = {s: cmd('docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', h).strip()
               for s,h in fixture.HOSTS.items()}
    host('source', 'mkdir', '-p', '/root/.ssh', '/run/sshd')
    host('source', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/tmp/hostkey')
    host('target', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/tmp/source-identity')
    public = host('target', 'cat', '/tmp/source-identity.pub')
    fixture.copy('source', public, '/root/.ssh/authorized_keys')
    # This secret is synthetic and carried only on stdin/private files, never printed.
    password = 'synthetic-relay-password-'+OP
    host('source', 'chpasswd', data='root:'+password+'\n')
    config = 'Port 2222\nListenAddress 0.0.0.0\nHostKey /tmp/hostkey\nPermitRootLogin yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nLogLevel VERBOSE\nPidFile /tmp/source-sshd.pid\n'
    fixture.copy('source', config, '/tmp/sshd_config')
    cmd('docker', 'exec', '-d', fixture.HOSTS['source'], '/usr/sbin/sshd', '-D', '-f', '/tmp/sshd_config', '-E', '/tmp/sshd.log')
    # Only the new VPS can reach old SSH. An administrator actor on the same
    # network cannot connect; all operations below go through the new VPS.
    host('source', 'iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '2222', '!', '-s', ADDRESS['target'], '-j', 'REJECT')
    actor = 'amnezia-migration-test-'+fixture.TOKEN+'-app'
    script = "import socket,sys; s=socket.socket(); s.settimeout(3); assert s.connect_ex((sys.argv[1],2222)) != 0; print('PASS: old SSH blocked from administrator network')"
    print(cmd('docker', 'run', '--rm', '--name', actor, '--network', fixture.NETWORK,
              '--entrypoint', 'python3', 'amnezia-local-vpn-tests', '-c', script, ADDRESS['source']).strip(), flush=True)
    stage = '/tmp/amnezia-migration-'+OP
    host('target', 'mkdir', '-m', '700', stage)
    host('target', 'cp', '/src/client/server_scripts/migration/agent.py', stage+'/agent.py')
    host('target', 'cp', '/src/client/server_scripts/migration/relay.py', stage+'/relay.py')
    SOURCE_IDENTITY = relay('discover-source', authorize=False, host=ADDRESS['source'], port=2222)['identity']
    SOURCE_CREDENTIALS = {'host': ADDRESS['source'], 'port': 2222, 'user': 'root', 'secret': password}
    logs = host('source', 'cat', '/tmp/sshd.log')
    assert 'Accepted ' not in logs and 'Failed password' not in logs
    # A wrong reviewed key fails BEFORE the password is presented.
    actual = dict(SOURCE_IDENTITY)
    host('target', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/tmp/wrong-hostkey')
    parts = host('target', 'cat', '/tmp/wrong-hostkey.pub').split()
    import base64
    SOURCE_IDENTITY = {**actual, 'key': parts[1], 'fingerprint': 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(parts[1])).digest()).decode().rstrip('=')}
    relay('source-command', command='status', expect=False)
    logs = host('source', 'cat', '/tmp/sshd.log')
    assert 'Accepted ' not in logs and 'Failed password' not in logs
    SOURCE_IDENTITY = actual
    # Password authentication works with OpenSSH ASKPASS, without sshpass or argv secrets.
    assert source('status')['phase'] == 'absent'
    assert 'Accepted password' in host('source', 'cat', '/tmp/sshd.log')
    # The bulk operation uses a key; exercise both actual authentication methods.
    SOURCE_CREDENTIALS['secret'] = host('target', 'cat', '/tmp/source-identity')
    fixture.traffic(clients, ADDRESS['source'])
    assert fixture.fetch(info, issued, ADDRESS['source'])['revision'] == '1'
    assert relay('start-stage', targetAddress=ADDRESS['target'])['phase'] == 'running'
    # The SSH control command already ended. Reconnect later to a detached job.
    time.sleep(2)
    assert relay('start-stage', targetAddress=ADDRESS['target']).get('phase') in ('running', None)
    for _ in range(240):
        result = relay('poll-stage', authorize=False)
        if result.get('phase') != 'running':
            break
        time.sleep(1)
    else:
        raise RuntimeError('Detached pull timed out')
    assert result['target']['phase'] == 'ready'
    assert result['source']['state'] == result['target']['state']
    # The raw archive lives only on the two VPSs; this driver/app never downloads it.
    host('target', 'python3', '-c', 'from pathlib import Path; p=Path("/var/lib/amnezia/migrations/'+OP+'"); assert not list(p.glob("ssh-*")); assert not (p/"pull-job/request.json").exists()')
    source('source-check')
    interrupt_after_first_stop('source', 'source-stop')
    assert source('status')['phase'] == 'stopping'
    # Continuation must reject configuration edits made during an interrupted stop.
    original = d('source', 'cp', 'amnezia-awg2:/opt/amnezia/awg/clientsTable', '-', binary=True)
    fixture.copy('source', 'changed-during-stop', '/tmp/changed-table')
    d('source', 'cp', '/tmp/changed-table', 'amnezia-awg2:/opt/amnezia/awg/clientsTable')
    rejected = relay('source-command', command='source-stop', expect=False)
    assert rejected['reason'] == 'source_changed'
    d('source', 'cp', '-', 'amnezia-awg2:/opt/amnezia/awg/', data=original, binary=True)
    source('source-stop')
    local('activate')
    fixture.traffic(clients, ADDRESS['target'])
    payload = fixture.fetch(info, issued, ADDRESS['target'])
    assert payload['revision'] == '1'
    exercise_application_admin_commands(info, payload['settings'])
    assert fixture.fetch(info, issued, ADDRESS['target'])['revision'] == '2'
    exercise_migrated_host_as_rollback_source()
    interrupt_after_first_stop('target', 'rollback-export')
    assert local('status')['phase'] == 'target-stopping'
    interrupt_rollback_after_source_start()
    assert relay('rollback-status')['phase'] == 'incomplete'
    assert relay('rollback')['phase'] == 'rolled-back'
    assert relay('rollback-status')['phase'] == 'rolled-back'
    assert relay('rollback')['phase'] == 'rolled-back'  # Final reply may have been lost.
    fixture.traffic(clients, ADDRESS['source'])
    assert fixture.fetch(info, issued, ADDRESS['source'])['revision'] == '2'
    source('finalize')
    local('finalize')
    print('PASS: blocked old SSH from app; new-host discovery without auth; wrong pin before password; password+key auth; detached direct pull; WG/AWG/DNS/old signed token; C++ subscription admin without tags; partial source/target stops + partial source restart + lost rollback reply retaining revision 2; temporary SSH secrets removed', flush=True)


if __name__ == '__main__':
    try:
        main()
    finally:
        for name in fixture.HOSTS.values():
            cmd('docker', 'rm', '-f', name, check=False)
        cmd('docker', 'network', 'rm', fixture.NETWORK, check=False)
