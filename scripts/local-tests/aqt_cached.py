#!/usr/bin/env python3
"""Keep verified Qt archives across image builds without patching installed aqt."""
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile

_original_download = None
_original_installer = None


def _download(url, output, algorithm, expected, timeout):
    return cached_download(_original_download, url, output, algorithm, expected, timeout)


def _patch_download():
    global _original_download
    from aqt import helper, installer
    if _original_download is None:
        _original_download = helper.downloadBinaryFile
    helper.downloadBinaryFile = _download
    installer.downloadBinaryFile = _download


def installer_worker(*args):
    # aqt3.3 explicitly uses spawn, not fork. Install the cache INSIDE each
    # worker; a parent-only monkey patch would silently redownload everything.
    from aqt import installer
    original = installer.installer
    if original is installer_worker:
        original = _original_installer
    _patch_download()
    return original(*args)


def cached_download(original, url, output, algorithm, expected, timeout):
    output = Path(output)
    if expected is None:
        raise ValueError("Qt archive checksum verification is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.with_name(output.name + ".lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if output.exists():
            digest = hashlib.new(algorithm)
            with output.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.digest() != expected:
                raise ValueError("Corrupt Qt archive retained; refusing overwrite: " + output.name)
            return
        fd, temporary = tempfile.mkstemp(prefix=output.name + ".download-", dir=output.parent)
        os.close(fd)
        # A failed download is retained under its unique partial name, never
        # mistaken for a verified archive or a successful installation.
        original(url, Path(temporary), algorithm, expected, timeout)
        digest = hashlib.new(algorithm)
        with open(temporary, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.digest() != expected:
            raise ValueError("Qt archive verification failed; partial retained")
        os.chmod(temporary, 0o444)
        os.replace(temporary, output)


def main():
    global _original_installer
    from aqt import installer
    from aqt.__main__ import main as aqt_main
    _original_installer = installer.installer
    _patch_download()
    installer.installer = installer_worker
    return aqt_main()


if __name__ == "__main__":
    main()
