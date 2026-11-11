"""Inputs that must match before replacing only an APK's Go JNI payload."""
import subprocess

# Native Go changes are deliberately separate; Kotlin, Qt, resources and build
# inputs cannot be replaced by injecting libwg-go.so into an older package.
HOST_PATHS = (
    'client', 'common', 'third_party', 'recipes', 'cmake', 'deploy',
    'CMakeLists.txt', 'CMakePresets.json', '.gitmodules',
    ':(exclude)client/tests/**', ':(exclude)**/src/test/**',
)


def changed_host_sources(baseline, cwd=None):
    return subprocess.check_output(
        ['git', 'diff', '--name-only', baseline, 'HEAD', '--', *HOST_PATHS],
        cwd=cwd, text=True,
    ).splitlines()
