"""Incremental owned Android package inputs; never delete a build tree."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stage(source, target, java, aar, notices, max_sdk=None, openvpn_notices=None):
    source, target, java, aar, notices = map(Path, (source, target, java, aar, notices))
    if not list(java.glob("net/openvpn/ovpn3/ClientAPI_*.java")):
        raise ValueError("Generated OpenVPN Java bindings from native package are missing")
    desired = {}

    def tree(root, prefix="", skip=None):
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part in {".git", ".gradle", "build", "__pycache__"} for part in relative.parts):
                continue
            if path.is_file() and not (skip and skip(relative)):
                desired[str(Path(prefix) / relative)] = (path.read_bytes(), path.stat().st_mode & 0o777)

    tree(source, skip=lambda p: str(p).startswith(("openvpn/src/main/java/", "openvpn/generated/java/")))
    tree(java, "openvpn/generated/java")
    tree(notices, "assets/routing-licenses")
    if openvpn_notices:
        tree(Path(openvpn_notices), "assets/routing-licenses/openvpn-cloak")
    desired["xray/libXray/" + aar.name] = (aar.read_bytes(), 0o644)
    if max_sdk:
        name = "AndroidManifest.xml"
        data, mode = desired[name]
        anchor = b'android:installLocation="auto">'
        if data.count(anchor) != 1:
            raise ValueError("Android manifest maxSdkVersion anchor changed")
        desired[name] = (data.replace(anchor, anchor + (
            '\n    <uses-sdk android:maxSdkVersion="%d" />' % int(max_sdk)).encode()), mode)
    target.mkdir(parents=True, exist_ok=True)
    manifest = target / ".amnezia-package-inputs.json"
    prior = json.loads(manifest.read_text()) if manifest.exists() else {}
    def owned_path(name):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid staged input path: " + name)
        path = target / relative
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != target.parent):
            raise ValueError("Symlink staged input retained: " + name)
        return path
    # Preflight ALL removals/changes before touching anything. An initial
    # adoption may retain identical existing files, never overwrite user work.
    for name, digest in prior.items():
        path = owned_path(name)
        if not path.is_file() or sha(path.read_bytes()) != digest:
            raise ValueError("Modified staged input retained: " + name)
    for name, (data, _) in desired.items():
        path = owned_path(name)
        if path.exists() and name not in prior and (not path.is_file() or path.read_bytes() != data):
            raise ValueError("Unowned staged input retained: " + name)
    written = 0
    for name, (data, mode) in desired.items():
        path = target / name
        if not path.exists() or path.read_bytes() != data:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            written += len(data)
        if path.stat().st_mode & 0o777 != mode:
            path.chmod(mode)
    for name in prior.keys() - desired.keys():
        (target / name).unlink()  # Verified owned input only, never a directory.
    data = json.dumps({name: sha(data) for name, (data, _) in desired.items()}, sort_keys=True).encode()
    if not manifest.exists() or manifest.read_bytes() != data:
        pending = manifest.with_suffix(".next")
        pending.write_bytes(data)
        pending.replace(manifest)
    return {"files": len(desired), "bytes_written": written}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "target", "java", "aar", "notices"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--max-sdk", type=int)
    parser.add_argument("--openvpn-notices")
    args = parser.parse_args()
    print(json.dumps(stage(**vars(args))))
