#!/usr/bin/env python3
"""Archive boundary regressions: never unpack arbitrary server files on a host."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('migration_agent', Path(__file__).parents[2]/'server_scripts/migration/agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def archive(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        for name, kind, content in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(content)
            else:
                member.linkname = str(content)
            tar.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return raw.getvalue()


class Archives(unittest.TestCase):
    def test_volume_rejects_traversal_absolute_symlink_hardlink_device_and_duplicates(self):
        cases = [[('../outside', tarfile.REGTYPE, b'secret')],
                 [('/etc/passwd', tarfile.REGTYPE, b'secret')],
                 [('link', tarfile.SYMTYPE, '/etc')],
                 [('hard', tarfile.LNKTYPE, '../../etc/passwd')],
                 [('device', tarfile.CHRTYPE, '')],
                 [('same', tarfile.REGTYPE, b'first'), ('same', tarfile.REGTYPE, b'last')]]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(agent.Rejected):
                agent.tar_hash(archive(entries))

    def test_config_hash_ignores_archive_order_and_timestamps(self):
        first = [('state.json', tarfile.REGTYPE, b'private-state'), ('tls.pem', tarfile.REGTYPE, b'private-cert')]
        self.assertEqual(agent.tar_hash(archive(first)), agent.tar_hash(archive(list(reversed(first)))))
        self.assertNotEqual(agent.tar_hash(archive(first)), agent.tar_hash(archive(first[:1])))

    def test_bundle_rejects_unknown_or_duplicate_entries_without_host_extraction(self):
        manifest = json.dumps({'version': 1, 'volume': False}).encode()
        valid = [('manifest.json', tarfile.REGTYPE, manifest), ('images.tar', tarfile.REGTYPE, b'images')]
        for extra in [[('../outside', tarfile.REGTYPE, b'bad')],
                      [('manifest.json', tarfile.REGTYPE, manifest)],
                      [('volume.tar', tarfile.SYMTYPE, '/etc/passwd')]]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = archive(valid+extra)
                (root/'incoming.tar').write_bytes(data)
                with self.assertRaises(agent.Rejected):
                    agent.unpack(root, hashlib.sha256(data).hexdigest())
                self.assertFalse((root.parent/'outside').exists())

    def test_digest_checked_before_unpacking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'incoming.tar').write_bytes(archive([('manifest.json', tarfile.REGTYPE, b'{}')]))
            with self.assertRaisesRegex(agent.Rejected, 'bundle_digest_mismatch'):
                agent.unpack(root, '0'*64)
            self.assertFalse((root/'manifest.json').exists())


class TargetOwnership(unittest.TestCase):
    def test_concurrent_foreign_volume_is_not_written(self):
        # Docker volume create is idempotent: another service can win the name
        # after preflight. Never restore into it just because create returned 0.
        manifest = {'network': None, 'volume': True}
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)/('a'*32)
            work.mkdir()
            (work/'images.tar').write_bytes(b'synthetic-images')
            with patch.object(agent, 'unpack', return_value=manifest), \
                 patch.object(agent, 'validate_target'), \
                 patch.object(agent.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(agent, 'run', return_value=b''), \
                 patch.object(agent, 'inspect', return_value={'Labels': {'foreign-service':'1'}}), \
                 patch.object(agent, 'restore_volume') as restore:
                with self.assertRaisesRegex(agent.Rejected, 'target_volume_ownership_changed'):
                    agent.import_target(work, {}, {'sha256':'synthetic'})
                restore.assert_not_called()


class FinalizationSecrets(unittest.TestCase):
    def test_interrupted_private_requests_and_keys_are_removed(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)/('b'*32)
            job = work/'pull-job'
            job.mkdir(parents=True, mode=0o700)
            (job/'request.json').write_text('{"secret":"synthetic-source-key"}')
            (job/'request.tmp').write_text('{"secret":"partial-synthetic-key"}')
            stale = work/'ssh-interrupted'
            stale.mkdir(mode=0o700)
            (stale/'identity').write_text('synthetic-private-key')
            stage = work/'user-stage'
            stage.mkdir(mode=0o700)
            (stage/'request-interrupted.json').write_text('synthetic-app-request-secret')
            (stage/'__pycache__').mkdir(mode=0o700)
            (stage/'__pycache__/agent.pyc').write_bytes(b'synthetic-cache')
            with patch.object(agent, 'client_stage', return_value=stage):
                agent.finalize(work, {'phase':'aborted'})
            self.assertFalse((stage/'request-interrupted.json').exists())
            self.assertFalse((stage/'__pycache__').exists())
            self.assertFalse((job/'request.json').exists())
            self.assertFalse((job/'request.tmp').exists())
            self.assertFalse(stale.exists())

    def test_live_worker_prevents_credential_deletion(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)/('b'*32)
            job = work/'pull-job'
            job.mkdir(parents=True, mode=0o700)
            request = job/'request.json'
            request.write_text('{"secret":"synthetic-source-key"}')
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)', '--worker', str(request)])
            try:
                with self.assertRaisesRegex(agent.Rejected, 'pull_job_busy'):
                    agent.finalize(work, {'phase':'aborted'})
                self.assertTrue(request.exists())
            finally:
                child.terminate()
                child.wait(timeout=5)


class ReplayFloor(unittest.TestCase):
    def setUp(self):
        self.original = {'host': 'vpn.example.test', 'signingKey': 'synthetic-signer',
                         'certificate': 'synthetic-certificate', 'tlsKey': 'synthetic-tls-key',
                         'records': {'one': {'id': 'one', 'tokenHash': 'synthetic-token-hash',
                                             'clientPublicKey': 'synthetic-client', 'container': 'amnezia-awg2',
                                             'revision': 2, 'revoked': True}}}

    def test_rollback_preserves_higher_revisions_and_revocations(self):
        latest = json.loads(json.dumps(self.original))
        latest['records']['one']['revision'] = 3
        agent.compatible_store(self.original, latest)

    def test_rollback_rejects_replay_identity_changes_and_token_resurrection(self):
        for key, value in [('revision', 1), ('revoked', False), ('tokenHash', 'other'),
                           ('clientPublicKey', 'other'), ('container', 'amnezia-wireguard')]:
            latest = json.loads(json.dumps(self.original))
            latest['records']['one'][key] = value
            with self.subTest(key=key), self.assertRaises(agent.Rejected):
                agent.compatible_store(self.original, latest)
        for key in ('host', 'signingKey', 'certificate', 'tlsKey'):
            latest = json.loads(json.dumps(self.original))
            latest[key] = 'different'
            with self.subTest(key=key), self.assertRaises(agent.Rejected):
                agent.compatible_store(self.original, latest)
        latest = json.loads(json.dumps(self.original))
        latest['records'] = {}
        with self.assertRaises(agent.Rejected):
            agent.compatible_store(self.original, latest)


if __name__ == '__main__':
    unittest.main()
