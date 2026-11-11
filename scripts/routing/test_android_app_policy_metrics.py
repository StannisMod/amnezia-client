#!/usr/bin/env python3
"""A two-app claim requires two UIDs and unchanged packet-tunnel ownership."""
import copy
import json
import unittest
from run_android_acceptance import app_policy_metrics

class AppPolicyEvidence(unittest.TestCase):
    def test_rejects_shared_uid_reconnect_or_missing_isolation(self):
        metrics={'uids':[10281,10282],'same_session':True,'same_old_ports':True,'dns_contexts_switched':True}
        resource={'pid':42,'capture_links':{'tun0':7},'capture_fds':1}
        report={'retained_resources':{'app_policy_before':resource,'app_policy_after':copy.deepcopy(resource)}}
        app_policy_metrics('APP_POLICY_RESULT '+json.dumps(metrics),report)
        for key,value in (('uids',[10281,10281]),('uids',[-1,10282]),('same_session',False),('same_old_ports',False),('dns_contexts_switched',False)):
            with self.subTest(field=key,value=value),self.assertRaises(AssertionError):
                app_policy_metrics('APP_POLICY_RESULT '+json.dumps({**metrics,key:value}),copy.deepcopy(report))
        for key,value in (('pid',43),('capture_links',{'tun0':8}),('capture_fds',2)):
            invalid=copy.deepcopy(report);invalid['retained_resources']['app_policy_after'][key]=value
            with self.subTest(resource=key),self.assertRaises(AssertionError):
                app_policy_metrics('APP_POLICY_RESULT '+json.dumps(metrics),invalid)

if __name__=='__main__':unittest.main()
