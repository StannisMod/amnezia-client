from conan import ConanFile
from conan.tools.files import get, copy, replace_in_file, apply_conandata_patches, export_conandata_patches
from conan.tools.gnu import Autotools, AutotoolsToolchain, AutotoolsDeps, PkgConfigDeps
from conan.tools.layout import basic_layout
from conan.tools.cmake import cmake_layout, CMakeToolchain, CMake, CMakeDeps

import os
import importlib.util
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

class Openvpn(ConanFile):
    name = "openvpn"
    version = "2.7.0"
    package_type = "application"
    settings = "os", "build_type", "arch", "compiler"

    @property
    def _is_windows(self):
        return str(self.settings.os).startswith("Windows")

    def export_sources(self):
        export_conandata_patches(self)
        copy(self, "*applink.c", src=self.recipe_folder, dst=self.export_sources_folder)
        copy(self, "native_dns.py", src=self.recipe_folder, dst=self.export_sources_folder)
        copy(self, "amnezia_dns.h", src=self.recipe_folder, dst=self.export_sources_folder)

    def layout(self):
        if self._is_windows:
            cmake_layout(self)
        else:
            basic_layout(self)

    def build_requirements(self):
        if self._is_windows:
            self.tool_requires("cmake/[>=4.2]")
        else:
            self.tool_requires("libtool/2.4.7")
            self.tool_requires("automake/1.16.5")

        if self.settings.os == "Linux" or self._is_windows:
            self.tool_requires("pkgconf/2.5.1")

    def requirements(self):
        # Keep dependency versions unified. Linux packaging additionally retains
        # the executable's actual library bytes independently of service copies.
        self.requires("openssl/3.6.2")
        self.requires("lz4/1.10.0", visible=False)
        self.requires("lzo/2.10", visible=False)
        if self.settings.os == "Linux":
            self.requires("libnl/3.9.0", visible=False)
            self.requires("libcap-ng/0.9.2", visible=False)
        if self._is_windows:
            self.requires("tap-windows6/[*]")

    def source(self):
        get(self, f"https://github.com/OpenVPN/openvpn/archive/refs/tags/v{self.version}.zip",
            sha256="1a65d8587f932c13d55b1f175ff2e1d61d795d9092788662e888054854d4ee3d", strip_root=True
        )

    def _patch_sources(self):
        spec = importlib.util.spec_from_file_location("native_openvpn_dns",
            str(Path(self.export_sources_folder) / "native_dns.py"))
        overlay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(overlay)
        overlay.apply(self.source_folder, self.export_sources_folder)
        replace_in_file(self, 
            os.path.join(self.source_folder, "CMakeLists.txt"),
            "/Qspectre",
            ""
        )

    def generate(self):
        self._patch_sources()

        if self.settings.os == "Linux" or self._is_windows:
            pkgconf = PkgConfigDeps(self)
            pkgconf.generate()

        if self._is_windows:
            tc = CMakeToolchain(self)
            applink_include_path = os.path.join(self.export_sources_folder, "include").replace("\\", "/")
            tap_include_path = (self.dependencies["tap-windows6"].cpp_info.aggregated_components().includedirs[0]).replace("\\", "/")
            tc.extra_cflags = [ f"-I{tap_include_path}", f"-I{applink_include_path}" ]
            tc.extra_cxxflags = [ f"-I{tap_include_path}", f"-I{applink_include_path}" ]
            tc.cache_variables["BUILD_TESTING"] = False
            tc.cache_variables["ENABLE_PKCS11"] = False
            tc.generate()
            deps = CMakeDeps(self)
            deps.generate()
        else:
            tc = AutotoolsToolchain(self)
            tc.configure_args.extend(["--disable-shared", "--enable-static"])
            tc.configure_args.append("--disable-plugins")
            if self.settings.os == "Linux":
                openssl_libdir = self.dependencies["openssl"].cpp_info.aggregated_components().libdirs[0]
                # pad the rpath so consumers can rewrite it in place (it cannot grow)
                padding = max(0, 256 - len(openssl_libdir) - 2)
                rpath = f"{openssl_libdir}:/" + "_" * padding
                tc.extra_ldflags.append(f"-Wl,-rpath,{rpath}")
            elif self.settings.os == "Macos":
                # reserve header space so consumers can rewrite rpaths via install_name_tool
                tc.extra_ldflags.append("-Wl,-headerpad_max_install_names")
            tc.generate()
            deps = AutotoolsDeps(self)
            deps.generate()

    def build(self):
        apply_conandata_patches(self)
        if self._is_windows:
            cmake = CMake(self)
            cmake.configure()
            cmake.build()
        else:
            at = Autotools(self)
            at.autoreconf()
            at.configure()
            at.make()

    def package(self):
        if self._is_windows:
            copy(self, "*openvpn.exe", src=self.build_folder, dst=self.package_folder, keep_path=False)
        else:
            copy(self, "openvpn", src=os.path.join(self.build_folder, "src", "openvpn"), dst=self.package_folder)
            if self.settings.os == "Linux":
                binary = Path(self.package_folder) / "openvpn"
                environment = dict(os.environ)
                environment.pop("LD_LIBRARY_PATH", None)
                environment.pop("LD_PRELOAD", None)
                output = subprocess.check_output(["ldd", str(binary)], env=environment, text=True)
                if "not found" in output:
                    raise RuntimeError("Unresolved native OpenVPN package dependency")
                libraries = {}
                for line in output.splitlines():
                    match = re.match(r"\s*(\S+) => (/\S+) \(", line)
                    if not match:
                        continue
                    name, path = match.groups()
                    source = Path(path).resolve()
                    if str(source).startswith(("/usr/lib/", "/lib/", "/lib64/")):
                        continue
                    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) or name in libraries:
                        raise RuntimeError("Ambiguous native OpenVPN dependency name")
                    destination = Path(self.package_folder) / "openvpn-libs" / name
                    destination.parent.mkdir(exist_ok=True)
                    shutil.copy2(source, destination)
                    digest = hashlib.sha256(source.read_bytes()).hexdigest()
                    if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                        raise RuntimeError("Native OpenVPN library bytes changed while packaging")
                    libraries[name] = digest
                (Path(self.package_folder) / "openvpn-runtime-source.json").write_text(json.dumps({
                    "source_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "libraries": libraries,
                }, indent=2) + "\n")

    def package_info(self):
        self.cpp_info.exe = True

        ext = ".exe" if self._is_windows else ""
        self.cpp_info.location = os.path.join(self.package_folder, f"openvpn{ext}")
