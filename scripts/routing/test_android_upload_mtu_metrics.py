#!/usr/bin/env python3
"""Acceptance must reject reconnects, fresh sockets and ineffective faults."""
import copy
import json
import unittest

from run_android_acceptance import upload_mtu_metrics


class UploadMTUEvidence(unittest.TestCase):
    def test_accepts_only_aged_original_connections_under_active_impairment(self):
        metrics = {'same_session': True, 'filter_still_active': True,
                   'original_tcp_accepts': 2, 'age_before_fault_ms': 65000}
        resources = {'pid': 42, 'capture_links': {'tun0': 7}, 'capture_fds': 1}
        report = {'dropped_outer_packets': {'restore_upload_mtu': 3},
                  'retained_resources': {'upload_mtu_before': resources,
                                         'upload_mtu_after': copy.deepcopy(resources)}}
        upload_mtu_metrics('MTU_UPLOAD_RESULT '+json.dumps(metrics), report)
        for key, bad in (('same_session', False), ('filter_still_active', False),
                         ('original_tcp_accepts', 3), ('age_before_fault_ms', 64999)):
            with self.subTest(metric=key), self.assertRaises(AssertionError):
                upload_mtu_metrics('MTU_UPLOAD_RESULT '+json.dumps({**metrics, key: bad}),
                                   copy.deepcopy(report))
        invalid = copy.deepcopy(report)
        invalid['dropped_outer_packets']['restore_upload_mtu'] = 0
        with self.assertRaises(AssertionError):
            upload_mtu_metrics('MTU_UPLOAD_RESULT '+json.dumps(metrics), invalid)
        for key, bad in (('pid', 43), ('capture_links', {'tun0': 8}), ('capture_fds', 2)):
            invalid = copy.deepcopy(report)
            invalid['retained_resources']['upload_mtu_after'][key] = bad
            with self.subTest(resource=key), self.assertRaises(AssertionError):
                upload_mtu_metrics('MTU_UPLOAD_RESULT '+json.dumps(metrics), invalid)


if __name__ == '__main__':
    unittest.main()
