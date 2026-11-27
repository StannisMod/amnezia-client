#!/usr/bin/env python3
"""Link current Linux service offline using an existing immutable Conan closure."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--target", choices=("AmneziaVPN-service", "AmneziaVPN"),
                        default="AmneziaVPN-service")
    parser.add_argument("--openvpn-package", type=Path,
                        help="Use a locally packaged frozen native candidate, without Conan resolution")
    parser.add_argument("--native-dns-runtime", type=Path,
                        help="Use a measured existing-runtime DNS archive/header without dependency resolution")
    parser.add_argument("--native-dns-evidence", type=Path,
                        help="Measured cache-builder evidence for the immutable runtime product")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    output = args.output
    os.environ.update(GOMODCACHE=str(args.cache / "go/modules"), GOPROXY="off", GOSUMDB="off")
    if args.openvpn_package:
        if not args.resume or not (args.openvpn_package / "openvpn-runtime-source.json").is_file():
            parser.error("--openvpn-package requires --resume and a recipe-packaged native closure")
        target = output / "conan/openvpn-Targets-release.cmake"
        text, count = re.subn(r'set\(openvpn_PACKAGE_FOLDER_RELEASE "[^"]+"\)',
            f'set(openvpn_PACKAGE_FOLDER_RELEASE "{args.openvpn_package}")', target.read_text())
        if count != 1:
            raise RuntimeError("Unexpected cached OpenVPN CMakeDeps target")
        target.write_text(text)
    if args.native_dns_runtime:
        runtime = args.native_dns_runtime
        if not args.resume:
            parser.error("--native-dns-runtime currently requires the owned --resume build")
        for name in ("amnezia_xray.a", "amnezia_xray.h"):
            if not (runtime / name).is_file():
                parser.error("Incomplete measured native DNS runtime: " + str(runtime / name))
        if args.native_dns_evidence:
            evidence = args.native_dns_evidence
            measured = json.loads((evidence / "result.json").read_text())
            for name, key in (("amnezia_xray.a", "archive_sha256"),
                              ("amnezia_xray.h", "header_sha256")):
                if hashlib.sha256((runtime / name).read_bytes()).hexdigest() != measured[key]:
                    parser.error("Measured native runtime bytes differ: " + name)
            graph = json.loads((evidence / "dependency-graph.json").read_text())
            before, after = graph["compiled_before"], graph["compiled_after"]
            module = "github.com/StannisMod/amnezia-client/native/routing/nativedns"
            if graph["only_added_module"] != module or set(after) - set(before) != {module}:
                parser.error("Unexpected added native dependencies")
        else:
            graph = json.loads((runtime / "native-dependency-graph.json").read_text())
            before, after = graph["compiled_modules_before"], graph["compiled_modules_after"]
        if any(after.get(key) != value for key, value in before.items()):
            parser.error("Native dependency versions changed")
        target = output / "conan/amnezia-xray-bindings-Targets-release.cmake"
        text = target.read_text()
        matches = re.findall(r'"([^"\n]+/amnezia_xray\.a)"', text)
        if len(matches) != 1:
            parser.error("Unknown cached native archive target")
        previous = str(Path(matches[0]).parent)
        for path in output.joinpath("conan").glob("*xray*cmake"):
            text = path.read_text()
            if previous in text:
                path.write_text(text.replace(previous, str(runtime)))
    if args.openvpn_package or args.native_dns_runtime:
        subprocess.run(["cmake", "-S", str(source), "-B", str(output / "build")], check=True)
    if args.resume:
        subprocess.run(["cmake", "--build", str(output / "build"), "--target",
                        args.target, "--parallel", "2"], check=True)
        return
    output.mkdir(parents=True, exist_ok=False)
    generators = output / "conan"
    shutil.copytree(args.cache / "build/conan", generators)
    # Only the existing Xray runtime is replaced by its measured DNS-enabled
    # build. All other imported package paths stay in the read-only cache.
    runtime = args.cache / "native-desktop-dns-20261123-v5"
    for path in generators.glob("*xray*cmake"):
        text = path.read_text()
        text = text.replace("/work/conan/p/b/amnezce5cc33d7266e/p/include", str(runtime))
        text = text.replace("${amnezia-xray-bindings_PACKAGE_FOLDER_RELEASE}/include", str(runtime))
        text = text.replace("${amnezia-xray-bindings_PACKAGE_FOLDER_RELEASE}/lib/libamnezia_xray.a",
                            str(runtime / "amnezia_xray.a"))
        path.write_text(text)
    hook = output / "frozen-dependencies.cmake"
    hook.write_text(
        'set_property(GLOBAL PROPERTY CONAN_INSTALL_SUCCESS TRUE)\n'
        f'set_property(GLOBAL PROPERTY CONAN_GENERATORS_FOLDER "{generators}")\n')
    print("Offline cached generators: no Conan install; recipe export command disabled explicitly",
          flush=True)
    subprocess.run([
        "cmake", "-S", str(source), "-B", str(output / "build"), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_PREFIX_PATH=/opt/Qt/6.10.1/gcc_64",
        f"-DCMAKE_PROJECT_INCLUDE={hook}", "-DCONAN_COMMAND=/bin/true",
        "-DAMNEZIA_CONAN_PREBUILTS=OFF", "-DBUILD_TRANSLATIONS=OFF",
    ], check=True)
    subprocess.run(["cmake", "--build", str(output / "build"), "--target",
                    args.target, "--parallel", "2"], check=True)


if __name__ == "__main__":
    main()
