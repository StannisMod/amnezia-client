#!/usr/bin/env python3
"""Compile real AWG/Protocol Kotlin modules independently of Qt/Conan."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    android = root / "client/android"
    work = args.build_dir.resolve()
    (work / "gradle").mkdir(parents=True, exist_ok=True)
    shutil.copy2(android / "gradle/libs.versions.toml", work / "gradle/libs.versions.toml")
    settings = '''import com.android.build.api.dsl.SettingsExtension
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
plugins { id("com.android.settings") version "8.5.2" }
rootProject.name = "AmneziaRoutingKotlinCheck"
include(":utils", ":protocolApi", ":wireguard", ":awg")
configure<SettingsExtension> { compileSdk=36; minSdk=28; buildToolsVersion="36.0.0" }
'''
    for module in ("utils", "protocolApi", "wireguard", "awg"):
        settings += f'project(":{module}").projectDir = file({json.dumps((android / module).as_posix())})\n'
    (work / "settings.gradle.kts").write_text(settings)
    (work / "build.gradle.kts").write_text('''plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
}
''')
    (work / "gradle.properties").write_text("android.useAndroidX=true\norg.gradle.jvmargs=-Xmx2g\n")
    command = [str(android / "gradlew"), "-p", str(work), ":awg:compileDebugKotlin", ":utils:testDebugUnitTest", "--no-daemon"]
    for attempt in range(3):
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, end="", flush=True)
        if result.returncode == 0:
            break
        # Retry dependency transport/resolution failures only; compiler failures
        # must remain visible on their first attempt.
        dependency_failure = any(marker in result.stdout for marker in (
            "Could not resolve all artifacts", "Could not resolve all files",
            "Could not GET", "Could not HEAD",
        ))
        wrapper_transport_failure = "org.gradle.wrapper." in result.stdout and any(marker in result.stdout for marker in (
            "SocketTimeoutException", "HTTP response code: 500", "HTTP response code: 502",
            "HTTP response code: 503", "HTTP response code: 504",
        ))
        dependency_failure = dependency_failure or wrapper_transport_failure
        if not dependency_failure or attempt == 2:
            raise subprocess.CalledProcessError(result.returncode, command)
        print("Retrying Gradle dependency resolution with refreshed metadata", flush=True)
        if "--refresh-dependencies" not in command:
            command.append("--refresh-dependencies")
        time.sleep(5 * (attempt + 1))


if __name__ == "__main__":
    main()
