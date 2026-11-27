#!/usr/bin/env python3
"""Measure real incremental Android package staging without a build-tree copy."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--openvpn-package", type=Path, required=True)
    p.add_argument("--aar", type=Path, required=True)
    p.add_argument("--notices", type=Path, required=True)
    args = p.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("stage_android", ROOT / "client/cmake/stage_android.py")
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    with Cache("/work/lab-cache").workspace("android-package-stage-sdk36") as work:
        target = work / "android-package-source-v2"
        kwargs = dict(source=ROOT / "client/android", target=target,
                      java=args.openvpn_package / "java", aar=args.aar, notices=args.notices,
                      openvpn_notices=args.openvpn_package / "licenses/cloak")
        first = stage.stage(**kwargs)
        def files():
            return {str(p.relative_to(target)): (sha256(p), p.stat().st_mtime_ns)
                    for p in target.rglob("*") if p.is_file()}
        before = files()
        second = stage.stage(**kwargs)
        if second["bytes_written"] != 0 or before != files():
            raise RuntimeError("Unchanged package staging rewrote its inputs")
        for name in ("native-cloak-provenance.json", "source/native-original-cloak.mod",
                     "source/native-original-cloak.sum"):
            path = target / "assets/routing-licenses/openvpn-cloak" / name
            if not path.is_file():
                raise RuntimeError("Original Cloak provenance is not staged: " + name)
        java = target / "openvpn/generated/java"
        for source in (args.openvpn_package / "java").rglob("*.java"):
            if sha256(source) != sha256(java / source.relative_to(args.openvpn_package / "java")):
                raise RuntimeError("Generated Java differs from its native package")
        if list((target / "openvpn/src/main/java").rglob("*.java")):
            raise RuntimeError("Old checked-in wrappers were staged")
        record = {"first": first, "second": second, "workspace": str(work),
                  "openvpn_package": str(args.openvpn_package),
                  "files": {name: value[0] for name, value in before.items()},
                  "scope": "actual package input staging and unchanged-input cache hit, not APK/device acceptance"}
        atomic_json(args.evidence / "result.json", record)
        (args.evidence / "result.json").chmod(0o644)
        print(json.dumps({key: record[key] for key in ("first", "second", "workspace", "scope")}))


if __name__ == "__main__":
    main()
