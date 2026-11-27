import copy
import hashlib
import io
import json
import tarfile
import unittest

from docker_image_config_digest import config_digest


def archive_bytes(configs, oci=False, manifest=True):
    output = io.BytesIO()
    rows = []
    with tarfile.open(fileobj=output, mode='w') as archive:
        for config in configs:
            raw = json.dumps(config, sort_keys=True).encode()
            digest = hashlib.sha256(raw).hexdigest()
            name = 'blobs/sha256/' + digest if oci else digest + '.json'
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
            rows.append({'Config': name, 'Layers': []})
        if manifest:
            raw = json.dumps(rows).encode()
            info = tarfile.TarInfo('manifest.json')
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    output.seek(0)
    return output


class ArchivedImageIdentity(unittest.TestCase):
    config = {'os': 'linux', 'architecture': 'amd64',
              'rootfs': {'type': 'layers', 'diff_ids': ['sha256:layer-a', 'sha256:layer-b']},
              'config': {'Env': ['FIXTURE=synthetic'], 'Entrypoint': ['dockerd']}}

    def test_same_config_across_archive_layouts(self):
        self.assertEqual(config_digest(archive_bytes([self.config]), 'linux', 'amd64'),
                         config_digest(archive_bytes([self.config], oci=True), 'linux', 'amd64'))

    def test_runtime_and_layer_changes_are_detected(self):
        original = config_digest(archive_bytes([self.config]), 'linux', 'amd64')
        for field in ('runtime', 'layers'):
            altered = copy.deepcopy(self.config)
            if field == 'runtime':
                altered['config']['Entrypoint'] = ['different-command']
            else:
                altered['rootfs']['diff_ids'].reverse()
            self.assertNotEqual(original, config_digest(archive_bytes([altered]), 'linux', 'amd64'))

    def test_missing_manifest_or_platform_is_rejected(self):
        with self.assertRaises(ValueError):
            config_digest(archive_bytes([self.config], manifest=False), 'linux', 'amd64')
        with self.assertRaises(ValueError):
            config_digest(archive_bytes([self.config]), 'linux', 'arm64')

    def test_ambiguous_platform_is_rejected(self):
        other = copy.deepcopy(self.config)
        other['config']['Env'] = ['FIXTURE=different']
        with self.assertRaises(ValueError):
            config_digest(archive_bytes([self.config, other]), 'linux', 'amd64')

    def test_other_platform_does_not_change_selected_identity(self):
        other = copy.deepcopy(self.config)
        other['architecture'] = 'arm64'
        self.assertEqual(config_digest(archive_bytes([self.config]), 'linux', 'amd64'),
                         config_digest(archive_bytes([other, self.config], oci=True), 'linux', 'amd64'))


if __name__ == '__main__':
    unittest.main()
