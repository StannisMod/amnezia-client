#!/usr/bin/env python3
"""Small shared lab cache. Cache hits never download, rebuild or rewrite inputs."""
import argparse
import contextlib
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.parse
if os.name == "nt":
    import msvcrt
else:
    import fcntl


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    if path.exists() and path.read_bytes() == data:
        return
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if os.name == "nt":
            if stream.seek(0, os.SEEK_END) == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield


class Cache:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def workspace(self, profile):
        # A profile identifies toolchain/ABI/purpose, NEVER the source commit.
        if not profile or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._" for c in profile):
            raise ValueError("Invalid cache profile")
        if profile in (".", ".."):
            raise ValueError("Invalid cache profile")
        with lock(self.root / "locks" / (profile + ".lock")):
            path = self.root / "workspaces" / profile
            if path.is_symlink():
                raise ValueError("Workspace symlink retained; refusing mutation")
            path.mkdir(parents=True, exist_ok=True)
            yield path

    def fetch(self, url, digest, size, online=False, opener=urllib.request.urlopen):
        """Immutable checksum/size-addressed download; resume only owned partials."""
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or size <= 0:
            raise ValueError("Expected SHA256 and positive byte length are required")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Downloads require HTTPS without URL credentials")
        directory = self.root / "downloads"
        directory.mkdir(exist_ok=True)
        final = directory / digest
        with lock(self.root / "locks" / (digest + ".lock")):
            if final.is_symlink():
                raise ValueError("Unexpected download symlink retained")
            if final.exists():
                if final.stat().st_size != size or sha256(final) != digest:
                    raise ValueError("Corrupt cached download retained; refusing overwrite")
                return final
            if not online:
                raise FileNotFoundError("Download not cached; explicit --online is required")
            part = directory / (digest + ".part")
            if part.is_symlink():
                raise ValueError("Unexpected partial-download symlink retained")
            offset = part.stat().st_size if part.exists() else 0
            if offset > size:
                raise ValueError("Oversized partial retained")
            if offset < size:
                headers = {"Range": f"bytes={offset}-"} if offset else {}
                with opener(urllib.request.Request(url, headers=headers), timeout=60) as response:
                    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                        raise ValueError("Non-HTTPS download redirect")
                    if offset:
                        if response.status != 206 or not response.headers.get("Content-Range", "").startswith(f"bytes {offset}-"):
                            raise ValueError("Server did not honor partial resume")
                    elif response.status != 200:
                        raise ValueError("Unexpected download status")
                    with part.open("ab" if offset else "wb") as stream:
                        while True:
                            chunk = response.read(1024 * 1024)
                            if not chunk:
                                break
                            offset += len(chunk)
                            if offset > size:
                                raise ValueError("Download exceeds expected size; partial retained")
                            stream.write(chunk)
                        stream.flush()
                        os.fsync(stream.fileno())
            if part.stat().st_size != size or sha256(part) != digest:
                raise ValueError("Download validation failed; partial retained")
            part.chmod(0o444)
            os.replace(part, final)
            return final


def sync_tree(source, destination, exclude=()):
    """Update only changed owned sources, preserving build/toolchain outputs.

    Use under Cache.workspace's lock through the whole subsequent build.
    Unknown edits are never overwritten; stale deletion is limited to previously
    manifested source files whose old digest still matches.
    """
    source, destination = Path(source).resolve(), Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest = destination / ".lab-sources.json"
    if manifest.is_symlink():
        raise ValueError("Unsafe cache manifest")
    previous = json.loads(manifest.read_text()) if manifest.exists() else {}
    desired = {}
    excluded = (".git", ".gradle", "__pycache__", "build", *exclude)
    for directory, dirs, files in os.walk(source):
        relative = Path(directory).relative_to(source)
        dirs[:] = sorted(name for name in dirs if not any(
            fnmatch.fnmatch(name, rule) or fnmatch.fnmatch((relative / name).as_posix(), rule)
            for rule in excluded))
        if any((Path(directory) / name).is_symlink() for name in dirs):
            raise ValueError("Source directory symlink requires explicit staging")
        for name in sorted(files):
            path = Path(directory) / name
            key = path.relative_to(source).as_posix()
            if any(fnmatch.fnmatch(name, rule) or fnmatch.fnmatch(key, rule) for rule in excluded):
                continue
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != source):
                raise ValueError("Source symlink requires explicit staging: " + key)
            if key == manifest.name:
                raise ValueError("Reserved cache manifest name")
            desired[key] = {"sha256": sha256(path), "mode": path.stat().st_mode & 0o777}
    copies, removals = [], []
    for key in sorted(set(previous) | set(desired)):
        if Path(key).is_absolute() or ".." in Path(key).parts:
            raise ValueError("Invalid source manifest path")
        target = destination / key
        if target.is_symlink() or not target.resolve().is_relative_to(destination):
            raise ValueError("Unsafe cache destination: " + key)
        if target.exists() and not target.is_file():
            raise ValueError("Non-file cache destination retained: " + key)
        current = sha256(target) if target.is_file() else None
        old = previous.get(key, {}).get("sha256")
        wanted = desired.get(key, {}).get("sha256")
        if current is not None and current not in (old, wanted):
            raise ValueError("Unowned/externally modified source retained: " + key)
        if wanted is None:
            if current is not None:
                removals.append(target)
        elif current != wanted:
            copies.append((source / key, target))
    written = 0
    for original, target in copies:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
        os.close(fd)
        try:
            shutil.copy2(original, temporary)
            written += original.stat().st_size
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    for target in removals:
        target.unlink()
    for key, data in desired.items():
        target = destination / key
        if target.stat().st_mode & 0o777 != data["mode"]:
            target.chmod(data["mode"])
    atomic_json(manifest, desired)
    return {"copied_files": len(copies), "removed_files": len(removals),
            "unchanged_files": len(desired) - len(copies), "bytes_written": written}


def ensure_image(tag, dockerfile, context, rebuild=False, build_args=()):
    """Reuse installed lab images by default; recipe upgrades are explicit.

    Existing legacy images are NOT relabeled as matching a new Dockerfile.
    Returned image ID is the actual measured provenance for consumers.
    """
    inspected = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", tag],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if inspected.returncode == 0 and not rebuild:
        return {"image": tag, "id": inspected.stdout.strip(), "cache_hit": True,
                "recipe_match": "not inferred for an existing image"}
    if not rebuild:
        raise FileNotFoundError("Lab image not installed; explicit --rebuild required")
    env = dict(os.environ, DOCKER_BUILDKIT="1")
    subprocess.run(["docker", "build", "--pull=false", "-t", tag, "-f", str(dockerfile),
                    *sum((["--build-arg", arg] for arg in build_args), []), str(context)],
                   env=env, check=True)
    result = ensure_image(tag, dockerfile, context)
    result["cache_hit"] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(os.environ.get(
        "AMNEZIA_LAB_CACHE", Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "amnezia-lab")))
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch")
    fetch.add_argument("url"); fetch.add_argument("sha256"); fetch.add_argument("size", type=int)
    fetch.add_argument("--online", action="store_true")
    image = commands.add_parser("image")
    image.add_argument("tag"); image.add_argument("--dockerfile", required=True, type=Path)
    image.add_argument("--context", required=True, type=Path)
    image.add_argument("--rebuild", action="store_true")
    image.add_argument("--build-arg", action="append", default=[])
    sync = commands.add_parser("sync")
    sync.add_argument("profile"); sync.add_argument("source", type=Path)
    args = parser.parse_args()
    if args.command == "image":
        print(json.dumps(ensure_image(args.tag, args.dockerfile, args.context, args.rebuild, args.build_arg)))
        return
    cache = Cache(args.root)
    if args.command == "fetch":
        print(cache.fetch(args.url, args.sha256, args.size, args.online))
    else:
        with cache.workspace(args.profile) as work:
            print(json.dumps({"workspace": str(work), **sync_tree(args.source, work)}))


if __name__ == "__main__":
    main()
