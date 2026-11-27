#!/usr/bin/env python3
"""Offline incremental Kotlin/JNI-API checks; evidence contains no build tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/local-tests"))
from lab_cache import Cache, atomic_json, sha256, sync_tree
from prepare_cached_source import write_changed


def directory_bytes(path):
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=Path("/work/lab-cache"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--aar", type=Path, required=True)
    parser.add_argument("--aar-sha256", required=True)
    parser.add_argument("--openvpn-api", type=Path)
    parser.add_argument("--openvpn-api-sha256")
    parser.add_argument("--openvpn-java", type=Path,
                        help="Generated Java from the actual production JNI build, not a fixture")
    args = parser.parse_args()
    if args.openvpn_java and args.openvpn_api:
        raise ValueError("Select production Java OR compile-only API fixture")
    if args.openvpn_java and not list(args.openvpn_java.glob("net/openvpn/ovpn3/ClientAPI_*.java")):
        raise ValueError("Production generated Java package is missing")
    openvpn = bool(args.openvpn_api or args.openvpn_java)
    if sha256(args.aar) != args.aar_sha256:
        raise ValueError("JNI API fixture digest differs")
    if bool(args.openvpn_api) != bool(args.openvpn_api_sha256):
        raise ValueError("OpenVPN compile fixture requires its measured digest")
    if args.openvpn_api and sha256(args.openvpn_api) != args.openvpn_api_sha256:
        raise ValueError("OpenVPN API fixture digest differs")
    args.evidence.mkdir(exist_ok=False, parents=True)

    def evidence_json(name, value):
        path = args.evidence / name
        atomic_json(path, value)
        # Container-owned cache manifests stay private; public test metadata
        # must remain readable by the host user without chowning shared volumes.
        path.chmod(0o644)
    android = ROOT / "client/android"
    cache = Cache(args.cache_root)
    # Source commits/runs do NOT make new workspaces. Toolchain/ABI changes
    # require a separate explicit profile; Gradle tracks source/dependency deltas.
    with cache.workspace("android-native-dns-kotlin-sdk36-jdk17") as work:
        before = directory_bytes(work)
        generated = work / ".lab-generated.json"
        old = json.loads(generated.read_text()) if generated.exists() else {}
        current = {}

        def write(name, text):
            target = work / name
            data = text.encode()
            digest = hashlib.sha256(data).hexdigest()
            if target.exists() and sha256(target) not in (digest, old.get(name)):
                raise ValueError("Modified generated cache input retained: " + name)
            current[name] = digest
            return write_changed(target, data)

        stats = {}
        modules = ["utils", "protocolApi", "xray"]
        if openvpn:
            modules.append("openvpn")
        for module in modules:
            stats[module] = sync_tree(android / module, work / module)
        if args.openvpn_java:
            stats["openvpn-generated-java"] = sync_tree(args.openvpn_java, work / "openvpn/generated/java")
        write("gradle/libs.versions.toml", (android / "gradle/libs.versions.toml").read_text())
        settings = '''
import com.android.build.api.dsl.SettingsExtension
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
plugins { id("com.android.settings") version "8.5.2" }
rootProject.name = "CachedNativeDnsKotlinCheck"
include(":utils", ":protocolApi", ":xray")
project(":xray").buildFileName = "lab-build.gradle.kts"
configure<SettingsExtension> { compileSdk=36; minSdk=28; buildToolsVersion="36.0.0" }
'''
        if openvpn:
            settings += '\ninclude(":openvpn")\nproject(":openvpn").buildFileName = "lab-build.gradle.kts"\n'
        write("settings.gradle.kts", settings)
        write("build.gradle.kts", '''
plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
}
''')
        write("gradle.properties", "android.useAndroidX=true\norg.gradle.jvmargs=-Xmx1536m\n"
              "org.gradle.workers.max=2\norg.gradle.caching=true\nkotlin.compiler.execution.strategy=in-process\n")
        build = (android / "xray/build.gradle.kts").read_text()
        marker = 'implementation(project(":xray:libXray"))'
        if build.count(marker) != 1:
            raise ValueError("JNI API integration point changed")
        write("xray/lab-build.gradle.kts", build.replace(marker,
              "implementation(files(" + json.dumps(str(args.aar.resolve())) + "))"))
        if args.openvpn_api:
            write("openvpn/lab-build.gradle.kts",
                  (android / "openvpn/build.gradle.kts").read_text() + '''
// Explicit compile-only SWIG fixture, not a production JNI substitution.
android { sourceSets.getByName("main").java.setSrcDirs(emptyList<String>()) }
dependencies {
    compileOnly(files(%s))
    testImplementation(files(%s))
}
''' % (json.dumps(str(args.openvpn_api)), json.dumps(str(args.openvpn_api))))
        elif args.openvpn_java:
            write("openvpn/lab-build.gradle.kts", (android / "openvpn/build.gradle.kts").read_text())
        atomic_json(generated, current)
        source_manifest = {module: json.loads((work / module / ".lab-sources.json").read_text())
                           for module in modules}
        evidence_json("inputs.json", {
            "workspace": str(work), "source": source_manifest, "generated": current,
            "aar": str(args.aar.resolve()), "aar_sha256": args.aar_sha256,
            "openvpn_api": str(args.openvpn_api) if args.openvpn_api else None,
            "openvpn_api_sha256": args.openvpn_api_sha256,
            "openvpn_generated_java": ({str(p.relative_to(args.openvpn_java)): sha256(p)
                for p in args.openvpn_java.rglob("*.java")} if args.openvpn_java else None),
            "scope": "Kotlin tests and named JNI API sources only, not APK/device acceptance"})
        evidence_json("source-sync.json", stats)
        env = dict(os.environ, GRADLE_USER_HOME="/work/gradle",
                   ANDROID_USER_HOME="/work/android-user-home",
                   ANDROID_HOME="/work/android-sdk", ANDROID_SDK_ROOT="/work/android-sdk")
        command = ["sh", str(android / "gradlew"), "-p", str(work), "--offline", "--no-daemon",
                   "--max-workers=2", ":xray:testDebugUnitTest", ":protocolApi:testDebugUnitTest",
                    ":utils:testDebugUnitTest"]
        if openvpn:
            command.append(":openvpn:testDebugUnitTest")
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (args.evidence / "gradle.raw").write_bytes(result.stdout)
        text = result.stdout.decode("utf-8", errors="replace")
        (args.evidence / "gradle.log").write_text(text)
        print(text, flush=True)
        measured = {"workspace_bytes_before": before, "workspace_bytes_after": directory_bytes(work),
                    "source_bytes_written": sum(s["bytes_written"] for s in stats.values()),
                    "gradle_exit": result.returncode}
        evidence_json("storage.json", measured)
        suites = []
        for path in sorted(path for module in modules for path in
                           (work / module).glob("build/test-results/testDebugUnitTest/TEST-*.xml")):
            suite = ET.parse(path).getroot()
            record = {"name": suite.attrib["name"], **{
                key: int(suite.attrib.get(key, 0)) for key in ("tests", "failures", "errors", "skipped")}}
            suites.append(record)
            # Small measured results, not classes/jars/SDKs/build reports.
            (args.evidence / path.name).write_bytes(path.read_bytes())
        if result.returncode:
            # Preserve failing JUnit diagnostics BEFORE a later incremental
            # run replaces mutable workspace results. A compile failure may
            # leave older XML: these are diagnostics, never a current PASS.
            evidence_json("failed-junit-diagnostics.json", {
                "gradle_exit": result.returncode, "suites": suites,
                "scope": "diagnostics only; may include prior up-to-date suite artifacts"})
            raise SystemExit(result.returncode)
        if not suites or any(s["failures"] or s["errors"] or s["skipped"] for s in suites):
            raise RuntimeError("Missing or unsuccessful Kotlin test results")
        required = [("XrayNativeLifecycleTest", 8), ("XrayDnsPublicationTest", 9),
                    ("NativeDnsPlanTest", 12), ("ProtocolConfigIpv6Test", 9)]
        if openvpn:
            required.append(("OpenVpnPublicationTest", 9))
            required.append(("OpenVpnNativeLifecycleTest", 5))
            required.append(("OpenVpnDnsBindingsTest", 4))
            required.append(("OpenVpnDnsNetworkTest", 1))
            required.append(("OpenVpnEndpointTest", 2))
        for name, count in required:
            matching = [s for s in suites if s["name"].endswith("." + name)]
            if len(matching) != 1 or matching[0]["tests"] < count:
                raise RuntimeError("Required tests missing: " + name)
        if sum(s["tests"] for s in suites) < (109 if openvpn else 88):
            raise RuntimeError("Existing regression coverage missing")
        evidence_json("tests.json", suites)
        print(json.dumps({"tests": sum(s["tests"] for s in suites), **measured}), flush=True)


if __name__ == "__main__":
    main()
