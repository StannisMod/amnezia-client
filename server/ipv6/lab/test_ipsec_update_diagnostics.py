#!/usr/bin/env python3
"""Credential-safety checks for unexpected owned-lab update diagnostics."""
import json
import unittest

from test_ipsec_update import public_rejection_snapshot, public_update_log


class UpdateDiagnostics(unittest.TestCase):
    def test_environment_mounts_and_custom_values_are_not_disclosed(self):
        container = {
            'HostConfig': {'Privileged': True, 'ExtraHosts': ['private-host'],
                           'Binds': ['private-mount'], 'Memory': 1024,
                           'PortBindings': {'500/udp': [{'HostIp': 'private-address', 'HostPort': 'private-port'}]}},
            'Mounts': [{'Source': 'private-source'}],
            'Config': {'Env': ['PASSWORD=private-password'], 'Entrypoint': ['private-command'],
                       'User': 'private-user'},
        }
        result = public_rejection_snapshot(container, {'Config': {'Env': ['different-secret']}})
        serialized = json.dumps(result)
        self.assertNotIn('private-', serialized)
        self.assertNotIn('different-secret', serialized)
        self.assertFalse(result['environment_matches_image'])
        self.assertEqual(['ExtraHosts', 'Binds'], result['nondefault_host_fields'])
        self.assertEqual(1, result['mount_count'])
        self.assertEqual(1024, result['host']['Memory'])

    def test_credentials_are_redacted_before_bounding_the_log(self):
        text = ('registry error\n-----BEGIN RSA PRIVATE KEY-----\n' +
                'sensitive-key-body' * 4000 +
                '\n-----END RSA PRIVATE KEY-----\nprivate_key=another-secret\n'
                'VPN_PASSWORD=fixture-password\n"password": "json-secret"\n'
                ': PSK "ipsec-secret"\nERROR: registry unavailable\n')
        result = public_update_log(text)
        self.assertLessEqual(len(result), 32768)
        for secret in ('sensitive-key-body', 'another-secret', 'fixture-password', 'json-secret', 'ipsec-secret'):
            self.assertNotIn(secret, result)
        self.assertIn('ERROR: registry unavailable', result)


if __name__ == '__main__':
    unittest.main()
