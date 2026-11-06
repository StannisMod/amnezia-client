#!/usr/bin/env python3
"""Negative cases for the production dependency/package guard."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('routing_builddeps',Path(__file__).with_name('verify.py'))
deps=importlib.util.module_from_spec(spec);spec.loader.exec_module(deps)

class DependencyGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.pin=copy.deepcopy(deps.load_lock()['profiles']['desktop_android'])
        self.source=Path(self.temporary.name)
        for name in deps.SOURCE_FILES:
            path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'test fixture source')
            self.pin['source_sha256'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.resolved={'Path':'gvisor.dev/gvisor','Version':self.pin['upstream_version'],
                       'Replace':{'Path':self.pin['module'],'Version':self.pin['version']}}
        self.downloaded={'Path':self.pin['module'],'Version':self.pin['version'],'Sum':self.pin['sum'],
                         'GoModSum':self.pin['go_mod_sum'],'Dir':str(self.source)}
    def test_matching_resolution(self):
        deps.verify_resolution(self.resolved,self.downloaded,self.pin)
    def test_stock_and_unexpected_replacements_rejected(self):
        for replacement in [None,{'Path':str(self.source)},{'Path':self.pin['module'],'Version':'v0.0.0-unreviewed'}]:
            with self.subTest(replacement=replacement):
                row=copy.deepcopy(self.resolved)
                if replacement is None:row.pop('Replace')
                else:row['Replace']=replacement
                with self.assertRaises(ValueError):deps.verify_resolution(row,self.downloaded,self.pin)
    def test_wrong_original_version_rejected(self):
        self.resolved['Version']='v0.0.0-unreviewed'
        with self.assertRaises(ValueError):deps.verify_resolution(self.resolved,self.downloaded,self.pin)
    def test_changed_checksums_rejected(self):
        for key in ['Sum','GoModSum']:
            row=copy.deepcopy(self.downloaded);row[key]='h1:changed'
            with self.assertRaises(ValueError):deps.verify_resolution(self.resolved,row,self.pin)
    def test_changed_or_missing_source_rejected(self):
        path=self.source/'pkg/tcpip/transport/tcp/snd.go';path.write_bytes(b'changed')
        with self.assertRaises(ValueError):deps.verify_resolution(self.resolved,self.downloaded,self.pin)
        path.unlink()
        with self.assertRaises(ValueError):deps.verify_resolution(self.resolved,self.downloaded,self.pin)
    def test_release_runtime_identity_rejects_repro_and_wrong_scope(self):
        lock=deps.load_lock();pin=lock['profiles']['desktop_android']
        info={'mode':'fixed','fix_id':lock['fix_id'],'profile':'desktop_android',
              'upstream_version':pin['upstream_version'],'upstream_commit':pin['upstream_commit'],
              'module':pin['module'],'version':pin['version'],'sum':pin['sum'],'commit':pin['commit']}
        deps.verify_info(info,'desktop_android')
        for key in ['mode','profile','version','sum','commit']:
            broken=info.copy();broken[key]='changed'
            with self.assertRaises(ValueError):deps.verify_info(broken,'desktop_android')
        with self.assertRaises(ValueError):deps.verify_info(info,'apple')

class ArchiveGuardTests(unittest.TestCase):
    def metadata(self, scope='apple'):
        pin=deps.load_lock()['profiles'][scope]
        body=('path\tgithub.com/amnezia-vpn/amneziawg-apple\n'
              'mod\tgithub.com/amnezia-vpn/amneziawg-apple\t(devel)\t\n'
              'dep\tgvisor.dev/gvisor\t'+pin['upstream_version']+'\n'
              '=>\t'+pin['module']+'\t'+pin['version']+'\t'+pin['sum']+'\n'
              'build\t-tags=with_gvisor,amnezia_apple_bridge\n').encode()
        def text(value):
            size=len(value);encoded=bytearray()
            while size>=128:encoded.append((size&127)|128);size>>=7
            encoded.append(size);return bytes(encoded)+value
        return b'\xff Go buildinf:'+bytes([8,2])+bytes(16)+text(b'go1.27.1')+text(bytes(16)+body+bytes(16))
    def member(self,name,data):
        header=(name.ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'100644'.ljust(8)+str(len(data)).ljust(10)+'`\n').encode()
        return header+data+(b'\n' if len(data)%2 else b'')
    def test_flat_archive_identity(self):
        archive=b'!<arch>\n'+self.member('go.o/',self.metadata())
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'libwg-go.a';path.write_bytes(archive)
            self.assertEqual(deps.verify_archive_file(path,'apple')['profile'],'apple')
            with self.assertRaises(ValueError):deps.verify_archive_file(path,'desktop_android')
    def test_bsd_member_name(self):
        obj=self.metadata()
        archive=b'!<arch>\n'+self.member('#1/8',b'go.o\x00\x00\x00\x00'+obj)
        self.assertEqual(deps.archive_go_object(archive),obj)
    def test_missing_duplicate_and_truncated_objects_rejected(self):
        member=self.member('go.o/',self.metadata())
        for archive in [b'!<arch>\n',b'!<arch>\n'+member+member,b'!<arch>\n'+member[:-5]]:
            with self.assertRaises(ValueError):deps.archive_go_object(archive)
    def test_no_supported_inline_identity_rejected(self):
        for content in [b'no Go metadata',self.metadata()[:35]]:
            with self.assertRaises(ValueError):deps.inline_build_metadata(content)
    def test_unpatched_archive_metadata_rejected(self):
        data=self.metadata().replace(b'github.com/StannisMod/gvisor',b'github.com/UntrustedX/gvisor')
        info=deps.inline_build_metadata(data)[0]
        with self.assertRaises(ValueError):deps.verify_metadata(info,'apple')


if __name__=='__main__':unittest.main()
