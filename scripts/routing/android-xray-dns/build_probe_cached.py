#!/usr/bin/env python3
"""Build a TEST-ONLY APK from production Xray Kotlin and tagged fault JNI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256, sync_tree
from prepare_cached_source import write_changed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aar", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--evidence", type=Path, required=True)
    args = p.parse_args()
    if sha256(args.aar) != args.sha256:
        raise ValueError("Runtime probe JNI differs")
    args.evidence.mkdir(parents=True, exist_ok=False)
    cache = Cache("/work/lab-cache")
    android = ROOT / "client/android"
    with cache.workspace("android-xray-runtime-probe-sdk36-jdk17") as work:
        stats = {}
        for module in ("utils", "protocolApi", "xray"):
            stats[module] = sync_tree(android / module, work / module)
        stats["probe"] = sync_tree(Path(__file__).parent / "app", work / "probe")
        files = {
            "gradle/libs.versions.toml": (android / "gradle/libs.versions.toml").read_text(),
            "gradle.properties": "android.useAndroidX=true\norg.gradle.jvmargs=-Xmx1536m\n"
                "org.gradle.workers.max=2\norg.gradle.caching=true\nkotlin.compiler.execution.strategy=in-process\n",
            "settings.gradle.kts": '''
import com.android.build.api.dsl.SettingsExtension
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
plugins { id("com.android.settings") version "8.5.2" }
rootProject.name = "TestOnlyXrayDnsProbe"
include(":utils", ":protocolApi", ":xray", ":probe")
project(":xray").buildFileName = "lab-build.gradle.kts"
configure<SettingsExtension> { compileSdk=36; minSdk=28; buildToolsVersion="36.0.0" }
''',
            "build.gradle.kts": '''
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
}
''',
            "probe/build.gradle.kts": '''
plugins { alias(libs.plugins.android.application); alias(libs.plugins.kotlin.android) }
kotlin { jvmToolchain(17) }
android {
    namespace = "org.amnezia.vpn.frontendprobe"
    defaultConfig {
        applicationId = "org.amnezia.vpn.frontendprobe"
        targetSdk = 28
        versionCode = 1
        versionName = "test-only-native-dns-probe"
        ndk { abiFilters += "x86_64" }
    }
}
dependencies {
    implementation(project(":utils"))
    implementation(project(":protocolApi"))
    implementation(project(":xray"))
    implementation(libs.kotlinx.coroutines)
}
'''
        }
        marker = 'implementation(project(":xray:libXray"))'
        text = (android / "xray/build.gradle.kts").read_text()
        if text.count(marker) != 1:
            raise ValueError("JNI dependency integration changed")
        files["xray/lab-build.gradle.kts"] = text.replace(marker,
            "implementation(files(" + json.dumps(str(args.aar)) + "))")
        files["probe/build.gradle.kts"] += (
            "\ndependencies { implementation(files(" + json.dumps(str(args.aar)) + ")) }\n")
        prior_path = work / ".generated.json"
        prior = json.loads(prior_path.read_text()) if prior_path.exists() else {}
        generated = {}
        for name, data in files.items():
            target = work / name
            digest = hashlib.sha256(data.encode()).hexdigest()
            if target.exists() and sha256(target) not in (digest, prior.get(name)):
                raise ValueError("Externally modified generated probe input retained")
            write_changed(target, data.encode())
            generated[name] = digest
        atomic_json(prior_path, generated)
        sources = {module: {name: value for name, value in
            json.loads((work / module / ".lab-sources.json").read_text()).items()
            if not name.startswith("src/test/")} for module in stats}
        identity = {"sources": sources, "generated": generated, "jni_sha256": args.sha256,
                    "scope": "TEST-ONLY x86_64 APK; no production assets/signing/GUI claim"}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        product = cache.root / "products" / key
        apk, record = product / "xray-native-dns-runtime-probe.apk", product / "apk.json"
        hit = record.exists()
        if hit:
            if sha256(apk) != json.loads(record.read_text())["sha256"]:
                raise ValueError("Cached probe APK differs")
        else:
            env = dict(os.environ, ANDROID_HOME="/work/android-sdk", ANDROID_SDK_ROOT="/work/android-sdk",
                       GRADLE_USER_HOME="/work/gradle")
            command = ["sh", str(android / "gradlew"), "-p", str(work), "--offline", "--no-daemon",
                       "--max-workers=2", ":probe:assembleDebug"]
            result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (args.evidence / "gradle.raw").write_bytes(result.stdout)
            text = result.stdout.decode("utf-8", errors="replace")
            (args.evidence / "gradle.log").write_text(text)
            print(text, flush=True)
            if result.returncode:
                raise SystemExit(result.returncode)
            built = work / "probe/build/outputs/apk/debug/probe-debug.apk"
            product.mkdir(parents=True, exist_ok=False)
            os.replace(built, apk)  # Same-volume move; no duplicate APK copy.
            atomic_json(record, {"sha256": sha256(apk), "key": key, "identity": identity})
        result = {"apk": str(apk), "sha256": sha256(apk), "cache_hit": hit, "test_only": True,
                  "source_bytes_written": sum(s["bytes_written"] for s in stats.values())}
        atomic_json(args.evidence / "result.json", result)
        (args.evidence / "result.json").chmod(0o644)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
