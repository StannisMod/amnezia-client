#!/usr/bin/env python3
"""Incremental private source checkout, referencing read-only Git objects."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from lab_cache import atomic_json, sha256, sync_tree


def write_changed(path, data):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Unexpected metadata symlink retained")
    if path.exists() and path.read_bytes() == data:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(data)


def prepare(source, destination, git_metadata, git_common_metadata):
    destination = Path(destination)
    result = sync_tree(source, destination)
    git = destination / ".git"
    if git.exists() and not git.is_dir():
        raise ValueError("Existing Git metadata retained; expected private metadata directory")
    git.mkdir(exist_ok=True)
    if (git / "commondir").exists() or (git / "gitdir").exists():
        raise ValueError("Unexpected external Git metadata retained")
    result["git"] = sync_tree(git_common_metadata, git, exclude=(
        "objects", "logs", "modules", "HEAD", "index", "config", "config.worktree",
        "commondir", "gitdir", "*.lock", "*.sock"))
    written = 0
    for name in ("HEAD", "index"):
        written += write_changed(git / name, (Path(git_metadata) / name).read_bytes())
    # Reuse the mounted immutable object database, don't copy all packs for
    # each test run. An existing private object cache is retained untouched.
    objects = git / "objects/info"
    if not objects.resolve().is_relative_to(git.resolve()):
        raise ValueError("Unexpected Git object symlink retained")
    objects.mkdir(parents=True, exist_ok=True)
    written += write_changed(objects / "alternates",
                             (str(Path(git_common_metadata) / "objects") + "\n").encode())
    state_path = git / ".lab-git-config.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    for name in ("config", "config.worktree"):
        original = Path(git_common_metadata) / name
        if not original.exists():
            continue
        input_hash = sha256(original)
        target = git / name
        prior = state.get(name)
        if prior and target.exists():
            if sha256(target) != prior["output"]:
                raise ValueError("Externally modified private Git configuration retained")
            if prior["input"] == input_hash:
                continue
        fd, temporary = tempfile.mkstemp(dir=git)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(original.read_bytes())
            subprocess.run(["git", "config", "--file", temporary, "core.worktree", str(destination)],
                           check=True)
            written += write_changed(target, Path(temporary).read_bytes())
            state[name] = {"input": input_hash, "output": sha256(target)}
        finally:
            os.unlink(temporary)
    atomic_json(state_path, state)
    result["git_metadata_bytes_written"] = written
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "destination", "git_metadata", "git_common_metadata"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.destination, args.git_metadata, args.git_common_metadata)))
