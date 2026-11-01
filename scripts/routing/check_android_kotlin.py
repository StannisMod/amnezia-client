#!/usr/bin/env python3
"""Compile real AWG/Protocol Kotlin modules independently of Qt/Conan."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess


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
    subprocess.run([str(android / "gradlew"), "-p", str(work), ":awg:compileDebugKotlin", "--no-daemon"], check=True)


if __name__ == "__main__":
    main()
