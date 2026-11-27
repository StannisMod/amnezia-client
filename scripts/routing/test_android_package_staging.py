import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stage_android", ROOT / "client/cmake/stage_android.py")
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


class AndroidPackageStagingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source, self.target, self.java, self.notices = [
            self.root / name for name in ("source", "target", "java", "notices")]
        for path in (self.source, self.java, self.notices):
            path.mkdir()
        self.aar = self.root / "libxray.aar"
        self.aar.write_bytes(b"fixture")
        self.put(self.source / "AndroidManifest.xml", b'<manifest android:installLocation="auto">')
        self.put(self.source / "openvpn/src/main/java/stale.java", b"stale")
        self.put(self.java / "net/openvpn/ovpn3/ClientAPI_Test.java", b"generated")
        self.put(self.notices / "NOTICE", b"notice")

    @staticmethod
    def put(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def run_stage(self, **kwargs):
        return STAGE.stage(self.source, self.target, self.java, self.aar, self.notices, **kwargs)

    def test_incremental_no_rewrite_and_no_old_wrappers(self):
        self.assertGreater(self.run_stage()["bytes_written"], 0)
        wrapper = self.target / "openvpn/generated/java/net/openvpn/ovpn3/ClientAPI_Test.java"
        before = wrapper.stat().st_mtime_ns
        self.assertEqual(self.run_stage()["bytes_written"], 0)
        self.assertEqual(wrapper.stat().st_mtime_ns, before)
        self.assertFalse((self.target / "openvpn/src/main/java/stale.java").exists())

    def test_only_owned_removed_inputs_are_deleted(self):
        self.run_stage()
        build = self.target / "openvpn/build/classes/retained"
        self.put(build, b"build")
        (self.notices / "NOTICE").unlink()
        self.run_stage()
        self.assertFalse((self.target / "assets/routing-licenses/NOTICE").exists())
        self.assertEqual(build.read_bytes(), b"build")

    def test_modified_owned_input_blocks_every_change(self):
        self.run_stage()
        manifest = self.target / "AndroidManifest.xml"
        manifest.write_bytes(b"user work")
        self.aar.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Modified staged input"):
            self.run_stage()
        self.assertEqual((self.target / "xray/libXray/libxray.aar").read_bytes(), b"fixture")
        self.assertEqual(manifest.read_bytes(), b"user work")

    def test_unowned_input_not_overwritten(self):
        self.put(self.target / "AndroidManifest.xml", b"user work")
        with self.assertRaisesRegex(ValueError, "Unowned staged input"):
            self.run_stage()

    def test_max_sdk_is_incremental_and_reversible(self):
        self.run_stage(max_sdk=35)
        self.assertEqual(self.run_stage(max_sdk=35)["bytes_written"], 0)
        manifest = self.target / "AndroidManifest.xml"
        self.assertIn(b'android:maxSdkVersion="35"', manifest.read_bytes())
        self.run_stage()
        self.assertNotIn(b"maxSdkVersion", manifest.read_bytes())

    def test_missing_generated_abi_refuses_before_staging(self):
        (self.java / "net/openvpn/ovpn3/ClientAPI_Test.java").unlink()
        with self.assertRaisesRegex(ValueError, "bindings"):
            self.run_stage()
        self.assertFalse(self.target.exists())

    def test_target_symlink_never_writes_outside_workspace(self):
        self.run_stage()
        outside = self.root / "outside"
        outside.write_bytes(b"fixture")
        staged = self.target / "xray/libXray/libxray.aar"
        staged.unlink()
        staged.symlink_to(outside)
        self.aar.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Symlink staged input"):
            self.run_stage()
        self.assertEqual(outside.read_bytes(), b"fixture")

    def test_original_cloak_licenses_and_provenance_are_shipped(self):
        cloak = self.root / "cloak-notices"
        self.put(cloak / "native-cloak-provenance.json", b'{"original_modules":{}}')
        self.put(cloak / "golang.org/x/crypto/LICENSE", b"original license")
        self.run_stage(openvpn_notices=cloak)
        base = self.target / "assets/routing-licenses/openvpn-cloak"
        self.assertEqual((base / "golang.org/x/crypto/LICENSE").read_bytes(), b"original license")
        self.assertTrue((base / "native-cloak-provenance.json").is_file())


if __name__ == "__main__":
    unittest.main()
