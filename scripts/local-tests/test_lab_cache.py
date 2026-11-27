import hashlib
import io
import multiprocessing
from pathlib import Path
import tempfile
import sys
import subprocess
import unittest
from unittest.mock import patch

from lab_cache import Cache, ensure_image, sha256, sync_tree
from aqt_cached import cached_download, installer_worker
from prepare_cached_source import prepare


class Response(io.BytesIO):
    status = 200
    headers = {}

    def geturl(self):
        return "https://example.test/tool"


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = Cache(self.root / "cache")

    def test_second_download_has_zero_network_calls_and_zero_rewrites(self):
        payload = b"immutable toolchain" * 1024
        digest = hashlib.sha256(payload).hexdigest()
        calls = []

        def opener(request, timeout):
            calls.append(request.full_url)
            return Response(payload)

        first = self.cache.fetch("https://example.test/tool", digest, len(payload), True, opener)
        before = first.stat()
        second = self.cache.fetch("https://example.test/tool", digest, len(payload),
                                  opener=lambda *a, **k: self.fail("network on cache hit"))
        after = second.stat()
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_offline_miss_and_corrupt_download_do_not_fetch_or_overwrite(self):
        digest = hashlib.sha256(b"tool").hexdigest()
        with self.assertRaises(FileNotFoundError):
            self.cache.fetch("https://example.test/tool", digest, 4)
        path = self.cache.root / "downloads" / digest
        path.write_bytes(b"bad!")
        with self.assertRaisesRegex(ValueError, "Corrupt"):
            self.cache.fetch("https://example.test/tool", digest, 4, True,
                             lambda *a, **k: self.fail("corrupt hit must not fetch"))
        self.assertEqual(path.read_bytes(), b"bad!")

    def test_download_resumes_only_when_server_confirms_exact_range(self):
        payload = b"abcdef"
        digest = hashlib.sha256(payload).hexdigest()
        directory = self.cache.root / "downloads"
        directory.mkdir()
        part = directory / (digest + ".part")
        part.write_bytes(b"abc")

        def resume(request, timeout):
            self.assertEqual(request.get_header("Range"), "bytes=3-")
            response = Response(b"def")
            response.status = 206
            response.headers = {"Content-Range": "bytes 3-5/6"}
            return response

        final = self.cache.fetch("https://example.test/tool", digest, 6, True, resume)
        self.assertEqual(final.read_bytes(), payload)

    def test_bad_range_and_bad_hash_are_preserved_not_accepted(self):
        digest = hashlib.sha256(b"abcdef").hexdigest()
        directory = self.cache.root / "downloads"
        directory.mkdir()
        part = directory / (digest + ".part")
        part.write_bytes(b"abc")
        with self.assertRaisesRegex(ValueError, "resume"):
            self.cache.fetch("https://example.test/tool", digest, 6, True,
                             lambda *a, **k: Response(b"abcdef"))
        self.assertEqual(part.read_bytes(), b"abc")
        part.write_bytes(b"xxxxxx")
        with self.assertRaisesRegex(ValueError, "validation"):
            self.cache.fetch("https://example.test/tool", digest, 6, True)
        self.assertEqual(part.read_bytes(), b"xxxxxx")

    def test_incremental_workspace_second_sync_writes_zero_bytes(self):
        source = self.root / "source"
        source.mkdir()
        (source / "file.cpp").write_text("old")
        with self.cache.workspace("linux-qt6") as work:
            first = sync_tree(source, work)
            (work / "build").mkdir()
            (work / "build/product").write_bytes(b"cached output")
            before = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in
                      (work / "file.cpp", work / ".lab-sources.json", work / "build/product")}
            second = sync_tree(source, work)
            self.assertEqual(second["bytes_written"], 0)
            self.assertEqual(second["copied_files"], 0)
            for name, identity in before.items():
                path = work / ("build/product" if name == "product" else name)
                self.assertEqual(identity, (path.stat().st_ino, path.stat().st_mtime_ns))
            (source / "file.cpp").write_text("changed")
            third = sync_tree(source, work)
            self.assertEqual(third["bytes_written"], 7)
            self.assertEqual((work / "build/product").read_bytes(), b"cached output")
        self.assertEqual(first["bytes_written"], 3)

    def test_unknown_user_edit_and_stale_modified_source_are_retained(self):
        source = self.root / "source"
        source.mkdir()
        original = source / "file.cpp"
        original.write_text("source")
        with self.cache.workspace("native") as work:
            sync_tree(source, work)
            target = work / original.name
            target.write_text("user edit")
            with self.assertRaisesRegex(ValueError, "modified"):
                sync_tree(source, work)
            original.unlink()
            with self.assertRaisesRegex(ValueError, "modified"):
                sync_tree(source, work)
            self.assertEqual(target.read_text(), "user edit")

    def test_removes_only_unchanged_previously_owned_source(self):
        source = self.root / "source"
        source.mkdir()
        original = source / "obsolete.cpp"
        original.write_text("source")
        with self.cache.workspace("native") as work:
            sync_tree(source, work)
            (work / "unowned.log").write_text("retained")
            original.unlink()
            result = sync_tree(source, work)
            self.assertEqual(result["removed_files"], 1)
            self.assertEqual((work / "unowned.log").read_text(), "retained")

    def test_unsafe_profile_and_symlink_are_rejected(self):
        for profile in ("..", "../outside", "", "a/b"):
            with self.assertRaises(ValueError):
                with self.cache.workspace(profile):
                    self.fail("unsafe workspace")
        source = self.root / "source"
        source.mkdir()
        (source / "link").symlink_to("/etc/passwd")
        with self.cache.workspace("native") as work:
            with self.assertRaisesRegex(ValueError, "symlink"):
                sync_tree(source, work)

    def test_docker_cache_hit_never_builds_or_pulls(self):
        class Result:
            returncode = 0
            stdout = "sha256:existing\n"
        with patch("lab_cache.subprocess.run", return_value=Result()) as run:
            result = ensure_image("cached:local", "Dockerfile", ".")
            self.assertTrue(result["cache_hit"])
            self.assertEqual(result["id"], "sha256:existing")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][:3], ["docker", "image", "inspect"])

    def test_docker_missing_image_requires_explicit_build(self):
        class Result:
            returncode = 1
            stdout = ""
        with patch("lab_cache.subprocess.run", return_value=Result()) as run:
            with self.assertRaises(FileNotFoundError):
                ensure_image("missing:local", "Dockerfile", ".")
            self.assertEqual(run.call_count, 1)

    def test_explicit_docker_build_preserves_buildkit_layer_cache(self):
        class Result:
            def __init__(self, code, stdout=""):
                self.returncode, self.stdout = code, stdout
        with patch("lab_cache.subprocess.run", side_effect=[
                Result(1), Result(0), Result(0, "sha256:built\n")]) as run:
            result = ensure_image("tools:local", "Dockerfile", ".", True, ["VERSION=pinned"])
            command = run.call_args_list[1].args[0]
            self.assertIn("--pull=false", command)
            self.assertNotIn("--no-cache", command)
            self.assertEqual(run.call_args_list[1].kwargs["env"]["DOCKER_BUILDKIT"], "1")
            self.assertFalse(result["cache_hit"])

    def test_partial_download_symlink_does_not_touch_user_data(self):
        target = self.root / "user-data"
        target.write_bytes(b"keep")
        payload = b"expected immutable artifact"
        digest = hashlib.sha256(payload).hexdigest()
        directory = self.cache.root / "downloads"
        directory.mkdir()
        (directory / (digest + ".part")).symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.cache.fetch("https://example.test/tool", digest, len(payload), True,
                             lambda *a, **k: self.fail("unsafe download reached network"))
        self.assertEqual(target.read_bytes(), b"keep")

    def test_qt_verified_archive_hit_does_not_redownload_or_rewrite(self):
        output = self.root / "Qt.7z"
        payload = b"Qt archive fixture"
        calls = []

        def original(url, path, algorithm, expected, timeout):
            calls.append(url)
            path.write_bytes(payload)

        expected = hashlib.sha1(payload).digest()
        cached_download(original, "https://example.test/Qt.7z", output, "sha1", expected, (5, 5))
        before = output.stat()
        cached_download(lambda *a: self.fail("Qt cache hit downloaded again"),
                        "https://example.test/Qt.7z", output, "sha1", expected, (5, 5))
        self.assertEqual(calls, ["https://example.test/Qt.7z"])
        self.assertEqual((before.st_ino, before.st_mtime_ns),
                         (output.stat().st_ino, output.stat().st_mtime_ns))

    def test_qt_corrupt_archive_and_missing_checksum_are_not_accepted(self):
        output = self.root / "Qt.7z"
        output.write_bytes(b"bad")
        for expected in (None, hashlib.sha1(b"good").digest()):
            with self.assertRaises(ValueError):
                cached_download(lambda *a: self.fail("corrupt archive redownloaded"),
                                "https://example.test/Qt.7z", output, "sha1", expected, (5, 5))
        self.assertEqual(output.read_bytes(), b"bad")

    def test_qt_cache_survives_actual_spawn_worker(self):
        package = self.root / "fake-modules/aqt"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("")
        (package / "helper.py").write_text(
            "def downloadBinaryFile(*args):\n    raise AssertionError('network requested in spawned worker')\n")
        (package / "installer.py").write_text(
            "from .helper import downloadBinaryFile\n"
            "def installer(*args):\n    return downloadBinaryFile(*args)\n")
        output = self.root / "Qt.7z"
        output.write_bytes(b"verified archive")
        sys.path.insert(0, str(package.parent))
        try:
            with multiprocessing.get_context("spawn").Pool(1) as pool:
                pool.apply_async(installer_worker, ("https://example.test/Qt.7z", output, "sha1",
                                 hashlib.sha1(output.read_bytes()).digest(), (5, 5))).get(timeout=15)
        finally:
            sys.path.remove(str(package.parent))
        self.assertEqual(output.read_bytes(), b"verified archive")

    def test_git_objects_are_shared_and_second_checkout_has_no_rewrites(self):
        source = self.root / "repository"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / "source.cpp").write_text("tracked source")
        subprocess.run(["git", "-C", str(source), "add", "source.cpp"], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=CacheTest",
                        "-c", "user.email=cache@example.invalid", "commit", "-qm", "fixture"], check=True)
        destination = self.root / "private-source"
        metadata = source / ".git"
        prepare(source, destination, metadata, metadata)
        self.assertEqual(subprocess.check_output(["git", "-C", str(destination), "show", "HEAD:source.cpp"]),
                         b"tracked source")
        self.assertEqual([p.name for p in (destination / ".git/objects").iterdir()], ["info"])
        before = {str(p.relative_to(destination)): (p.stat().st_ino, p.stat().st_mtime_ns)
                  for p in destination.rglob("*") if p.is_file()}
        second = prepare(source, destination, metadata, metadata)
        self.assertEqual(second["bytes_written"], 0)
        self.assertEqual(second["git"]["bytes_written"], 0)
        self.assertEqual(second["git_metadata_bytes_written"], 0)
        after = {str(p.relative_to(destination)): (p.stat().st_ino, p.stat().st_mtime_ns)
                 for p in destination.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
