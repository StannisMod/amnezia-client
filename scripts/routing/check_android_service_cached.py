#!/usr/bin/env python3
"""Reuse the existing full deployment tree; compile current service against named JNI."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256, sync_tree
from prepare_cached_source import write_changed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--aar", type=Path, required=True)
    p.add_argument("--aar-sha256", required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--openvpn-java", type=Path)
    p.add_argument("--openvpn-baseline", type=Path,
                   help="Retained Kotlin runner inputs manifest for initial OpenVPN adoption")
    args = p.parse_args()
    if sha256(args.aar) != args.aar_sha256:
        raise ValueError("JNI digest differs")
    args.evidence.mkdir(parents=True, exist_ok=False)
    with Cache("/work/lab-cache").workspace("android-full-service-existing-deployment") as ownership:
        manifest = ownership / "sources.json"
        prior = json.loads(args.baseline.read_text())
        if manifest.exists():
            prior.update(json.loads(manifest.read_text()))
        if args.openvpn_baseline:
            measured = json.loads(args.openvpn_baseline.read_text())["source"]["openvpn"]
            for name, record in measured.items():
                prior.setdefault("openvpn/" + name, record["sha256"])
        android = ROOT / "client/android"
        sources = [android / "src/org/amnezia/vpn/AmneziaVpnService.kt"]
        for module in ("utils", "protocolApi", "xray") + (("openvpn",) if args.openvpn_java else ()):
            sources.extend(sorted((android / module / "src/main").rglob("*.kt")))
            if module != "openvpn":
                sources.extend(sorted((android / module / "src/main").rglob("*.java")))
        if args.openvpn_java:
            sources.append(android / "openvpn/build.gradle.kts")
        desired = {str(path.relative_to(android)): sha256(path) for path in sources}
        # Validate everything before writing; never discard unrelated deployment edits.
        for name, digest in desired.items():
            target = args.project / name
            if target.exists() and sha256(target) not in (digest, prior.get(name)):
                raise ValueError("Unowned deployment change retained: " + name)
        written = 0
        for name in desired:
            source, target = android / name, args.project / name
            if not target.exists() or sha256(target) != desired[name]:
                data = source.read_bytes()
                write_changed(target, data)
                written += len(data)
        atomic_json(manifest, desired)
        generated_java = None
        if args.openvpn_java:
            generated_java = sync_tree(args.openvpn_java, args.project / "openvpn/generated/java")
        # Select an owned alternative build file before configuration/resolution.
        # Preserve the historical v200 recipe and its named old JNI fixture.
        init = ownership / "jni.init.gradle"
        jni_build = args.project / "xray/libXray/lab-current-jni.gradle.kts"
        content = ('configurations { maybeCreate("default") }\n'
                   'artifacts.add("default", file(' + json.dumps(str(args.aar)) + '))\n')
        build_record = ownership / "jni-build.json"
        old_build = json.loads(build_record.read_text()) if build_record.exists() else {}
        import hashlib
        digest = hashlib.sha256(content.encode()).hexdigest()
        if jni_build.exists() and sha256(jni_build) not in (digest, old_build.get("sha256")):
            raise ValueError("Unowned JNI build override retained")
        write_changed(jni_build, content.encode())
        atomic_json(build_record, {"sha256": digest})
        script = '''
gradle.settingsEvaluated { settings ->
    def p = settings.findProject(':xray:libXray')
    if (p != null) p.buildFileName = 'lab-current-jni.gradle.kts'
}
'''
        write_changed(init, script.encode())
        inputs = {"sources": desired, "aar": str(args.aar), "aar_sha256": args.aar_sha256,
                  "openvpn_java": str(args.openvpn_java) if args.openvpn_java else None,
                  "generated_java_sync": generated_java,
                  "project": str(args.project), "source_bytes_written": written,
                  "scope": "current service/app Kotlin compile only, not APK or JNI invocation"}
        atomic_json(args.evidence / "inputs.json", inputs)
        (args.evidence / "inputs.json").chmod(0o644)
        env = dict(os.environ, ANDROID_HOME="/work/android-sdk",
                   ANDROID_USER_HOME="/work/android-user-home",
                   ANDROID_SDK_ROOT="/work/android-sdk", GRADLE_USER_HOME="/work/gradle")
        result = subprocess.run(["sh", str(android / "gradlew"), "-p", str(args.project),
                                 "--offline", "--no-daemon", "--max-workers=2",
                                 "--init-script", str(init), ":compileOssDebugKotlin"],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (args.evidence / "gradle.raw").write_bytes(result.stdout)
        text = result.stdout.decode("utf-8", errors="replace")
        (args.evidence / "gradle.log").write_text(text)
        print(text, flush=True)
        atomic_json(args.evidence / "result.json", {"exit": result.returncode, **inputs})
        (args.evidence / "result.json").chmod(0o644)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
