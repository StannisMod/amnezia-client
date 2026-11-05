#!/usr/bin/env python3
"""New-host pull coordinator. No archive ever traverses the administrator app.

OpenSSH authenticates the old host only after the reviewed key has matched.
Credentials arrive in an exclusive mode0600 request, never argv, and are removed
at read time. A detached bulk job survives disconnection of the administrator.
"""
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import agent
from agent import Rejected, require


def privileged(command):
    return 'if test "$(id -u)" = 0; then '+command+'; else sudo -n '+command+'; fi'


def discovery(host, port):
    require(isinstance(host, str) and len(host) <= 253 and type(port) is int and 1 <= port <= 65535, 'invalid_source_address')
    require(shutil.which('ssh') and shutil.which('ssh-keyscan'), 'openssh_client_required_on_target')
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses.sort(key=lambda item: item[0] != socket.AF_INET)
    for family, _, _, _, endpoint in addresses[:8]:
        address = str(ipaddress.ip_address(endpoint[0]))
        r = subprocess.run(['ssh-keyscan', '-T', '5', '-p', str(port), '-t', 'ed25519,ecdsa,rsa', address],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
        keys = []
        for line in r.stdout.decode().splitlines():
            words = line.split()
            if len(words) == 3 and words[1] in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa'):
                blob = base64.b64decode(words[2], validate=True)
                require(len(blob) <= 16384, 'invalid_source_host_key')
                fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
                keys.append({'address': address, 'algorithm': words[1], 'key': words[2], 'fingerprint': fingerprint})
        if keys:
            return sorted(keys, key=lambda k: (k['algorithm'] != 'ssh-ed25519', k['algorithm'] == 'ssh-rsa'))[0]
    raise Rejected('source_unreachable_from_target')


class Source:
    def __init__(self, req, work):
        self.req, self.work = req, work
        self.credentials, self.identity = req['source'], req['sourceIdentity']
        self.temp = None
        self.stage = '/tmp/amnezia-migration-'+work.name

    def __enter__(self):
        c, identity = self.credentials, self.identity
        address = str(ipaddress.ip_address(identity['address']))
        require(re.fullmatch(r'[a-z_][a-z0-9_-]*[$]?', c['user']), 'invalid_source_login')
        require(type(c['port']) is int and 1 <= c['port'] <= 65535, 'invalid_source_port')
        blob = base64.b64decode(identity['key'], validate=True)
        expected = 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        require(expected == identity['fingerprint'], 'invalid_approved_source_key')
        algorithm = identity['algorithm']
        require(algorithm in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa'), 'invalid_source_key_algorithm')
        # The per-operation coordinator lock excludes a live worker here. Clear
        # private SSH files left by a killed process before creating new ones.
        directory = work_path(self.work.name)
        for stale in directory.glob('ssh-*'):
            if stale.is_dir() and not stale.is_symlink():
                shutil.rmtree(stale)
        self.temp = tempfile.TemporaryDirectory(prefix='ssh-', dir=directory)
        directory = Path(self.temp.name)
        try:
            known = directory/'known_hosts'
            host = address if c['port'] == 22 else '['+address+']:'+str(c['port'])
            known.write_text(host+' '+algorithm+' '+identity['key']+'\n')
            os.chmod(known, 0o600)
            algorithms = 'rsa-sha2-512,rsa-sha2-256' if algorithm == 'ssh-rsa' else algorithm
            self.argv = ['ssh', '-F', '/dev/null', '-p', str(c['port']), '-l', c['user'],
                         '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(known),
                         '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms='+algorithms,
                         '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
                         '-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
                         '-o', 'ClearAllForwardings=yes', '-o', 'KbdInteractiveAuthentication=no',
                         '-o', 'NumberOfPasswordPrompts=1', '-o', 'RequestTTY=no']
            self.env = {**os.environ, 'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': 'amnezia-migration:0'}
            secret = c['secret']
            require(isinstance(secret, str) and 0 < len(secret) <= 65536, 'invalid_source_credentials')
            if 'PRIVATE KEY' in secret and 'BEGIN' in secret:
                key = directory/'identity'
                key.write_text(secret.rstrip()+'\n')
                os.chmod(key, 0o600)
                self.argv += ['-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-i', str(key)]
            else:
                password = directory/'password'
                password.write_text(secret)
                os.chmod(password, 0o600)
                askpass = directory/'askpass'
                askpass.write_text('#!/bin/sh\nexec cat -- '+shlex.quote(str(password))+'\n')
                os.chmod(askpass, 0o700)
                self.env['SSH_ASKPASS'] = str(askpass)
                self.argv += ['-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no']
            self.argv += ['--', address]
            return self
        except BaseException:
            self.temp.cleanup()
            raise

    def __exit__(self, *unused):
        self.temp.cleanup()

    def command(self, command, data=None, output=None, timeout=180, allow_failure=False):
        def limit():
            maximum = agent.MAX if output is not None else 4*1024**2
            resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
        with tempfile.TemporaryFile() as capture:
            result = subprocess.run(self.argv+[command], input=data if isinstance(data, bytes) else None,
                                    stdin=data if data is not None and not isinstance(data, bytes) else None,
                                    stdout=output if output is not None else capture, stderr=subprocess.DEVNULL,
                                    env=self.env, timeout=timeout, preexec_fn=limit)
            require(result.returncode == 0 or allow_failure, 'source_ssh_failed_check_status')
            if output is not None:
                return b''
            capture.seek(0)
            return capture.read(4*1024**2+1)

    def bootstrap(self):
        path = shlex.quote(self.stage)
        self.command('umask 077; mkdir -p -- '+path+'; test ! -L '+path+
                     ' && test "$(stat -c \'%a:%u\' -- '+path+')" = "700:$(id -u)"')
        content = Path(__file__).with_name('agent.py').read_bytes()
        remote = shlex.quote(self.stage+'/agent.py')
        existing = self.command('if test -e '+remote+'; then test ! -L '+remote+' && sha256sum -- '+remote+'; fi').decode().strip()
        if existing:
            require(existing.startswith(hashlib.sha256(content).hexdigest()+' '), 'source_agent_changed')
        else:
            self.command('umask 077; set -C; cat > '+remote, data=content)

    def call(self, action, **params):
        request = json.dumps({'operation': self.work.name, 'action': action, **params}).encode()
        raw = self.command(privileged('python3 '+shlex.quote(self.stage+'/agent.py')), data=request, timeout=1800, allow_failure=True)
        result = json.loads(raw)
        require(result.get('version') == 1 and result.get('ok'), result.get('reason', 'unknown_source_result'))
        return result

    def pull(self, snapshot):
        require(type(snapshot['bytes']) is int and 0 <= snapshot['bytes'] <= agent.MAX, 'invalid_snapshot_size')
        expected = str(agent.ROOT/self.work.name/'bundle.tar')
        require(snapshot['file'] == expected, 'invalid_snapshot_path')
        path = self.work/'incoming.tar'
        with open(path, 'wb', opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as out:
            self.command(privileged('cat -- '+shlex.quote(expected)), output=out, timeout=1800)
            out.flush()
            os.fsync(out.fileno())
        require(path.stat().st_size == snapshot['bytes'] and agent.digest(path) == snapshot['sha256'], 'pull_digest_mismatch')

    def push_rollback(self, snapshot):
        path = self.work/'rollback.tar'
        require(str(path) == snapshot['file'] and agent.digest(path) == snapshot['sha256'], 'rollback_digest_mismatch')
        destination = shlex.quote(self.stage+'/rollback.tar')
        try:
            self.command('rm -f -- '+destination)
            with open(path, 'rb') as source:
                self.command('umask 077; set -C; cat > '+destination, data=source)
            self.call('rollback-import', sha256=snapshot['sha256'])
        finally:
            self.command('rm -f -- '+destination)

    def cleanup(self):
        self.command('rm -f -- '+shlex.quote(self.stage+'/agent.py')+' '+shlex.quote(self.stage+'/rollback.tar')+
                     '; if test -d '+shlex.quote(self.stage)+'; then rmdir -- '+shlex.quote(self.stage)+'; fi')


def work_path(operation):
    require(re.fullmatch('[a-f0-9]{32}', operation), 'invalid_operation')
    agent.ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(agent.ROOT, 0o700)
    work = agent.ROOT/operation
    work.mkdir(exist_ok=True, mode=0o700)
    return work


def local(work, action, **params):
    return agent.main({'operation': work.name, 'action': action, **params})


def stage(req, work):
    with Source(req, work) as source:
        source.bootstrap()
        a, b = source.call('status'), local(work, 'status')
        if a['phase'] == 'absent':
            a = source.call('export')
        require(a['phase'] == 'exported', 'source_snapshot_incomplete_restore_operation')
        if b['phase'] == 'absent':
            source.pull(a)
            b = local(work, 'import', sha256=a['sha256'])
        require(b['phase'] in ('staged', 'validated', 'ready'), 'target_import_incomplete_restore_operation')
        source.call('source-check')
        local(work, 'probe-remove')
        local(work, 'verify')
        try:
            probes = local(work, 'probe-create', address=req['targetAddress'])
            source.call('probe-run', configs=probes['configs'], address=req['targetAddress'])
            local(work, 'probe-remove')
            local(work, 'probe-confirm')
        finally:
            local(work, 'probe-remove')
        return {'version': 1, 'source': a, 'target': local(work, 'status')}


def job_status(work):
    directory = work/'pull-job'
    if (directory/'result.json').exists():
        return json.loads((directory/'result.json').read_bytes())
    if (directory/'pid.json').exists():
        pid = json.loads((directory/'pid.json').read_bytes())
        stat = Path('/proc')/str(pid['pid'])/'stat'
        if stat.exists() and stat.read_text().split()[21] == pid['start']:
            return {'version': 1, 'phase': 'running'}
    return {'version': 1, 'phase': 'interrupted'}


def start_job(req, work):
    directory = work/'pull-job'
    if directory.exists():
        previous = job_status(work)
        if previous.get('phase') == 'running' or previous.get('ok'):
            return previous
        # A finished failed request has no active worker and may be retried.
        require(previous.get('phase') == 'interrupted' or previous.get('ok') is False, 'pull_job_busy')
        (directory/'request.json').unlink(missing_ok=True)
        (directory/'result.json').unlink(missing_ok=True)
    else:
        directory.mkdir(mode=0o700)
    request = directory/'request.json'
    agent.save(request, {**req, 'action': 'run-stage'})
    try:
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker', str(request)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True, close_fds=True)
    except BaseException:
        request.unlink(missing_ok=True)
        raise
    stat = Path('/proc')/str(process.pid)/'stat'
    agent.save(directory/'pid.json', {'pid': process.pid, 'start': stat.read_text().split()[21]})
    return {'version': 1, 'phase': 'running'}


def main(req):
    require(os.geteuid() == 0, 'root_required')
    work = work_path(req['operation'])
    action = req['action']
    if action == 'discover-source':
        return {'version': 1, 'identity': discovery(req['host'], req['port'])}
    if action == 'poll-stage':
        return job_status(work)
    if action == 'start-stage' and (work/'pull-job').exists():
        previous = job_status(work)
        if previous.get('phase') == 'running' or previous.get('ok'):
            return previous
    # Serialize coordinator commands, including starts, against the worker. The
    # detached worker locks separately so the starter need not wait for completion.
    with open(work/'relay.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected('pull_job_busy')
        if action == 'start-stage':
            return start_job(req, work)
        if action == 'run-stage':
            return stage(req, work)
        with Source(req, work) as source:
            source.bootstrap()
            if action == 'source-command':
                command = req['command']
                require(command in ('status', 'source-check', 'source-stop', 'abort', 'finalize'), 'invalid_source_command')
                result = source.call(command)
                if command == 'finalize':
                    source.cleanup()
                return result
            if action == 'rollback':
                a, b = source.call('status'), local(work, 'status')
                if b['phase'] in ('active', 'rollback-exported') or (b['phase'] == 'stopped' and a['phase'] == 'stopped'):
                    latest = local(work, 'rollback-export')
                    if latest.get('file'):
                        source.push_rollback(latest)
                else:
                    local(work, 'abort')
                if a['phase'] != 'absent':
                    source.call('abort')
                return {'version': 1, 'phase': 'rolled-back'}
    raise Rejected('invalid_relay_action')


def respond(req):
    try:
        return {'ok': True, **main(req)}
    except (Rejected, OSError, ValueError, KeyError, subprocess.TimeoutExpired, agent.tarfile.TarError):
        # Never include subprocess stderr, passwords, key material or archives.
        error = sys.exc_info()[1]
        return {'ok': False, 'version': 1, 'reason': str(error) if isinstance(error, Rejected) else 'relay_failed_check_status'}


def read_request(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256*1024, 'invalid_private_request')
    require(path.stat().st_mode & 0o077 == 0, 'request_permissions_not_private')
    try:
        return json.loads(path.read_bytes())
    finally:
        path.unlink()


if __name__ == '__main__':
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        path = Path(sys.argv[2])
        request = read_request(path)
        # The parent may still hold the coordinator lock while storing the PID.
        for attempt in range(50):
            result = respond(request)
            if result.get('reason') != 'pull_job_busy':
                break
            time.sleep(.1)
        agent.save(path.parent/'result.json', result)
    else:
        try:
            request = read_request(Path(sys.argv[1])) if len(sys.argv) == 2 else json.loads(sys.stdin.buffer.read(256*1024+1))
            result = respond(request)
        except (Rejected, OSError, ValueError):
            result = {'version': 1, 'ok': False, 'reason': 'invalid_private_request'}
        print(json.dumps(result))
        sys.exit(0 if result.get('ok') else 1)
