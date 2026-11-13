"""Verify deployment command boundaries without touching the host's network."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "server_scripts/prepare_ipv6_network.sh"
FAKE = '''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['TRACE'],'a') as output:output.write(json.dumps([name,*args])+'\\n')
mode=os.environ['SCENARIO']
if name=='ip':
 if mode!='no-route':print('default via fd00::1 dev eth0')
 sys.exit(0)
if args[:1]!=['docker']:sys.exit(10)
args=args[1:]
if args==['network','create','--help']:
 print('--ipv4' if mode!='old-docker' else '--ipv6');sys.exit(0)
if args[:2]==['network','inspect']:
 exists=mode in ('existing','foreign') or Path(os.environ['CREATED']).exists()
 if not exists:sys.exit(1)
 if '--format' in args:
  template=args[args.index('--format')+1]
  if template=='{{.Id}}':print('a'*64)
  elif '.Containers' in template:print('yes' if mode=='attached' or Path(os.environ['CREATED']+'.connected').exists() else '')
  else:print('bridge true false '+('foreign' if mode=='foreign' or (mode=='replaced' and args[-1]=='a'*64) else 'v1'))
 sys.exit(0)
if args[:2]==['network','create']:
 Path(os.environ['CREATED']).write_text('created');print('network-id');sys.exit(0)
if args[:1]==['inspect']:
 print('b'*64);sys.exit(0)
if args[:2]==['network','connect']:
 Path(os.environ['CREATED']+'.connected').touch();sys.exit(0)
if args[:1]==['exec']:
 connected=Path(os.environ['CREATED']+'.connected').exists()
 if 'ip' in args:print('changed' if mode=='changed-route' and connected else 'default via 172.18.0.1 dev eth0')
 elif args[-1]=='/proc/net/route':print('changed' if mode=='changed-route' and connected else 'eth0 00000000 010012AC 0003 0 0 0 00000000')
 elif 'cat' in args:print('changed' if mode=='changed-dns' and connected else 'nameserver 127.0.0.11')
 else:sys.exit(12)
 sys.exit(0)
sys.exit(11)
'''

class IPv6NetworkPreparation(unittest.TestCase):
    def scenario(self, mode, attach=False, container='amnezia-wireguard'):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            for name in ('sudo', 'ip'):
                path = folder / name
                path.write_text(FAKE)
                path.chmod(0o755)
            trace = folder / 'trace'
            environment = dict(os.environ, PATH=str(folder)+os.pathsep+os.environ['PATH'],
                               TRACE=str(trace), CREATED=str(folder/'created'), SCENARIO=mode)
            invocation = ['/bin/sh', '-c', '. "$1"; amnezia_attach_ipv6_network "$2"', 'sh', str(SCRIPT), container] if attach else ['/bin/sh', str(SCRIPT)]
            result = subprocess.run(invocation, env=environment, text=True, capture_output=True)
            commands = [json.loads(line) for line in trace.read_text().splitlines()]
            return result, commands

    def test_new_bridge_is_ipv6_only_and_owned(self):
        result, commands = self.scenario('new')
        self.assertEqual(result.returncode, 0, result.stderr)
        creation = [c for c in commands if c[:4] == ['sudo','docker','network','create'] and '--help' not in c]
        self.assertEqual(len(creation), 1)
        self.assertIn('--ipv4=false', creation[0])
        self.assertIn('--ipv6', creation[0])
        self.assertIn('com.amnezia.ipv6-egress=v1', creation[0])
        self.assertIn('bridge-prepared-egress-unverified', result.stdout)

    def test_existing_owned_bridge_is_reused(self):
        result, commands = self.scenario('existing')
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any('--subnet' in command for command in commands))

    def test_foreign_bridge_is_not_modified(self):
        result, commands = self.scenario('foreign')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('existing-network-conflict', result.stderr)
        self.assertFalse(any('--subnet' in c or 'rm' in c for c in commands))

    def test_attachment_uses_immutable_ids_and_preserves_existing_endpoint(self):
        result, commands = self.scenario('new', attach=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        connects = [c for c in commands if c[:4] == ['sudo', 'docker', 'network', 'connect']]
        self.assertEqual(connects, [['sudo', 'docker', 'network', 'connect', 'a'*64, 'b'*64]])
        result, commands = self.scenario('attached', attach=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[:4] == ['sudo','docker','network','connect'] for c in commands))

    def test_attachment_rechecks_ownership_by_immutable_network_id(self):
        result, commands = self.scenario('replaced', attach=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c[:4] == ['sudo','docker','network','connect'] for c in commands))
        self.assertTrue(any(c[-1] == 'a'*64 and 'inspect' in c for c in commands))

    def test_attachment_changes_fail_without_destructive_disconnect(self):
        for mode in ('changed-route', 'changed-dns'):
            result, commands = self.scenario(mode, attach=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('attachment-changed-ipv4-or-dns', result.stderr)
            self.assertFalse(any('disconnect' in c or 'rm' in c for c in commands))

    def test_missing_route_or_capability_makes_no_network(self):
        for mode in ('no-route', 'old-docker'):
            result, commands = self.scenario(mode)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(any('--subnet' in c for c in commands))

    def test_proxy_attachment_needs_no_iproute_package_and_keeps_ipv4(self):
        for container in ('amnezia-xray', 'amnezia-ssxray'):
            result, commands = self.scenario('new', attach=True, container=container)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sum(c[-2:]==['cat','/proc/net/route'] for c in commands),2)
            self.assertFalse(any('ip' in c and c[:3]==['sudo','docker','exec'] for c in commands))
        result, commands = self.scenario('changed-route', attach=True, container='amnezia-xray')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('attachment-changed-ipv4-or-dns',result.stderr)

if __name__ == '__main__':
    unittest.main()
