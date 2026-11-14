#!/usr/bin/env python3
"""A two-app claim requires two UIDs and unchanged packet-tunnel ownership."""
import copy
import json
import unittest
from run_android_acceptance import app_policy_metrics

class AppPolicyEvidence(unittest.TestCase):
    def test_rejects_shared_uid_reconnect_or_missing_isolation(self):
        metrics={'uids':[10281,10282],'same_session':True,'same_old_ports':True,'dns_contexts_switched':True}
        isolated={'parent_uid':10281,'before':{'uid':99001,'delegated_echo':True,'delegated_port':48000,'tcp':'ANDROID_PERMISSION_DENIED','udp':'ANDROID_PERMISSION_DENIED'},'after':{'uid':99002,'delegated_echo':True,'delegated_port':48000}}
        metrics['isolated_process']=isolated
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
        for phase,key,value in (('before','uid',10281),('after','delegated_echo',False),('after','delegated_port',48001),('before','tcp','DIRECT'),('before','udp','DIRECT:app-policy-proof')):
            invalid=copy.deepcopy(metrics);invalid['isolated_process'][phase][key]=value
            with self.subTest(isolated_field=key,value=value),self.assertRaises(AssertionError):
                app_policy_metrics('APP_POLICY_RESULT '+json.dumps(invalid),copy.deepcopy(report))

if __name__=='__main__':unittest.main()
