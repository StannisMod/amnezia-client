#!/usr/bin/env python3
"""Credential-file and process-exposure boundaries of the new-host coordinator."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).parents[2]/'server_scripts/migration'))
import relay


class PrivateRequests(unittest.TestCase):
    def test_private_request_deleted_even_when_json_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'request.json'
            path.write_text('{invalid synthetic secret')
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                relay.read_request(path)
            self.assertFalse(path.exists())

    def test_public_file_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'request.json'
            path.write_text('{}')
            path.chmod(0o644)
            with self.assertRaises(relay.Rejected):
                relay.read_request(path)
            path.chmod(0o600)
            link = Path(root)/'link'
            link.symlink_to(path)
            with self.assertRaises(relay.Rejected):
                relay.read_request(link)

    def test_credentials_not_in_argv_or_environment_and_files_removed(self):
        original = relay.agent.ROOT
        with tempfile.TemporaryDirectory() as root:
            relay.agent.ROOT = Path(root)
            try:
                operation = 'a'*32
                work = relay.work_path(operation)
                blob = b'synthetic-ed25519-host-key'
                key = base64.b64encode(blob).decode()
                fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
                req = {'source': {'user':'root', 'port':22, 'secret':'synthetic-source-password'},
                       'sourceIdentity': {'address':'192.0.2.17', 'algorithm':'ssh-ed25519', 'key':key, 'fingerprint':fingerprint}}
                stale = work/'ssh-interrupted'
                stale.mkdir(mode=0o700)
                (stale/'identity').write_text('synthetic-key-from-interrupted-job')
                with relay.Source(req, work) as source:
                    self.assertFalse(stale.exists())
                    self.assertNotIn(req['source']['secret'], ' '.join(source.argv))
                    self.assertNotIn(req['source']['secret'], json.dumps(source.env))
                    private = Path(source.temp.name)
                    self.assertEqual((private/'password').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((private/'known_hosts').stat().st_mode & 0o777, 0o600)
                    self.assertNotIn('ForwardAgent=yes', source.argv)
                self.assertFalse(private.exists())
            finally:
                relay.agent.ROOT = original


if __name__ == '__main__':
    unittest.main()
