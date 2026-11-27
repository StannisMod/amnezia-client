#!/usr/bin/env python3
"""Execute real recipe packaging and production deployment using cached bytes."""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from conan.api.output import ConanOutput
from build_cached_openvpn_dns import native_dependencies

parser = argparse.ArgumentParser()
parser.add_argument("--native", type=Path)
parser.add_argument("--cmake-deps", type=Path)
parser.add_argument("--service-crypto", type=Path)
parser.add_argument("--service", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if args.cmake_deps:
    text = (args.cmake_deps / "openvpn-Targets-release.cmake").read_text()
    match = re.search(r'set\(openvpn_PACKAGE_FOLDER_RELEASE "([^"]+)"\)', text)
    if not match:
        parser.error("Cannot locate the actual Conan OpenVPN package")
    args.native = Path(match.group(1)) / "openvpn"
if not args.native:
    parser.error("--native or --cmake-deps is required")
if args.service:
    args.service_crypto = Path(native_dependencies(args.service)["libcrypto.so.3"]["path"])
if not args.service_crypto:
    parser.error("--service-crypto or --service is required")
root = Path(__file__).resolve().parents[2]
out = args.output
out.mkdir(exist_ok=False)
native = args.native.resolve()
baseline = native_dependencies(native)
recipe = root / "recipes/openvpn/conanfile.py"
spec = importlib.util.spec_from_file_location("openvpn_recipe_under_test", recipe)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
build = out / "recipe-build"
(build / "src/openvpn").mkdir(parents=True)
shutil.copy2(native, build / "src/openvpn/openvpn")
package = out / "package"
package.mkdir()
# Run the actual package() implementation and Conan file-copy helper. No graph
# resolution, exports or package downloads; only its build/package context is supplied.
context = SimpleNamespace(_is_windows=False, settings=SimpleNamespace(os="Linux"),
                          build_folder=str(build), package_folder=str(package), output=ConanOutput())
module.Openvpn.package(context)
assert hashlib.sha256((package / "openvpn").read_bytes()).hexdigest() == hashlib.sha256(native.read_bytes()).hexdigest()
helper = root / "cmake/deploy_openvpn_linux.cmake"


def deploy(source, destination, failure=False):
    result = subprocess.run(["cmake", f"-DOPENVPN_SOURCE={source / 'openvpn'}",
        f"-DOPENVPN_DESTINATION={destination}", "-P", str(helper)],
        capture_output=True, text=True)
    (out / (destination.parent.name + "-deployment.log")).write_text(result.stdout + result.stderr)
    if failure:
        assert result.returncode != 0 and "checksum mismatch" in result.stderr
        return
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    actual = native_dependencies(destination / "openvpn")
    assert actual.keys() == baseline.keys()
    assert all(actual[name]["sha256"] == baseline[name]["sha256"] for name in baseline)
    assert actual["libcrypto.so.3"]["path"] != str(args.service_crypto.resolve())
    return actual


destination = out / "normal/bin"
destination.mkdir(parents=True)
shutil.copy2(args.service_crypto, destination / "libcrypto.so.3")
service_hash = hashlib.sha256((destination / "libcrypto.so.3").read_bytes()).hexdigest()
closure = deploy(package, destination)
assert hashlib.sha256((destination / "libcrypto.so.3").read_bytes()).hexdigest() == service_hash
print("PASS: actual recipe + production CMake deployment retain exact native closure despite service libcrypto collision", flush=True)
relocated = out / "relocated-package"
shutil.copytree(package, relocated)
subprocess.run(["patchelf", "--set-rpath", "/unavailable/producer/conan-cache",
                str(relocated / "openvpn")], check=True)
metadata = json.loads((relocated / "openvpn-runtime-source.json").read_text())
metadata["source_sha256"] = hashlib.sha256((relocated / "openvpn").read_bytes()).hexdigest()
(relocated / "openvpn-runtime-source.json").write_text(json.dumps(metadata))
deploy(relocated, out / "relocated/bin")
print("PASS: recipe package relocates without the producer cache/RPATH", flush=True)
corrupt = out / "corrupt-package"
shutil.copytree(package, corrupt)
with (corrupt / "openvpn-libs/libcrypto.so.3").open("ab") as file:
    file.write(b"checksum-negative-case")
deploy(corrupt, out / "corrupt/bin", failure=True)
print("PASS: corrupt packaged dependency rejected before deployment", flush=True)
source_hash = hashlib.sha256((package / "openvpn").read_bytes()).hexdigest()
same = subprocess.run(["cmake", f"-DOPENVPN_SOURCE={package / 'openvpn'}",
    f"-DOPENVPN_DESTINATION={package}", "-P", str(helper)], capture_output=True, text=True)
assert same.returncode and "must not modify its source" in same.stderr
assert hashlib.sha256((package / "openvpn").read_bytes()).hexdigest() == source_hash
assert source_hash == hashlib.sha256(native.read_bytes()).hexdigest()
print("PASS: source package/cache is immutable; self-deployment is rejected", flush=True)
(out / "report.json").write_text(json.dumps({
    "recipe_sha256": hashlib.sha256(recipe.read_bytes()).hexdigest(),
    "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
    "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
    "baseline": baseline, "deployed": closure,
    "validation": "passed",
}, indent=2))
