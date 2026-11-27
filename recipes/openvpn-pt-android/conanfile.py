from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain
from conan.tools.files import copy, apply_conandata_patches, export_conandata_patches
from conan.tools.scm import Git
from conan.errors import ConanInvalidConfiguration

import os
import importlib.util
from pathlib import Path

class OpenvpnPtAndroid(ConanFile):
    name = "openvpn-pt-android"
    version = "1.0.0"
    package_type = "shared-library"
    settings = "os", "arch", "build_type", "compiler"

    def export_sources(self):
        export_conandata_patches(self)
        for pattern in ("native_dns*", "prepare_cloak_dns.py"):
            copy(self, pattern, self.recipe_folder, self.export_sources_folder)
        routing = Path(self.recipe_folder).parents[1] / "native/routing"
        for pattern in ("*.go", "*.mod", "*.sum", "*.json", "go.mod", "go.sum"):
            copy(self, pattern, str(routing),
                 str(Path(self.export_sources_folder) / "routing"))

    def layout(self):
        cmake_layout(self, src_folder="src")

    def build_requirements(self):
        self.tool_requires("swig/4.1.1")
        self.tool_requires("go/1.27.1")
        self.tool_requires("cmake/[>=3.4.1 <4]")

    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} only supports Android, got {self.settings.os}")

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/amnezia-vpn/openvpn-pt-android.git",
            target=".",
            args=["--recurse-submodules", "--branch", "update-ovpn3"]
        )

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["AMNEZIA_DNS_CLOAK_SOURCE"] = str(Path(self.build_folder) / "native-dns-cloak")
        tc.generate()

    def _prepare_dns(self):
        support = Path(self.export_sources_folder)
        def load(name):
            spec = importlib.util.spec_from_file_location(name, support / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        source = Path(self.source_folder)
        build = Path(self.build_folder)
        load("prepare_cloak_dns").prepare(
            source / "cloak", build / "native-dns-cloak", support / "routing", support)
        overlay = build / "native-dns-include"
        for name, data in load("native_dns").prepare(source / "openvpn3", support).items():
            target = overlay / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists() or target.read_bytes() != data:
                target.write_bytes(data)
        # Only tiny owned overlays are written. Original source/build/SDK trees
        # and frozen dependency versions are not copied or upgraded.
        cmake = source / "CMakeLists.txt"
        text = cmake.read_text()
        marker = "# AMNEZIA_NATIVE_DNS_OVERLAY"
        original = build / "native-dns-original-CMakeLists.txt"
        owned = build / "native-dns-owned-CMakeLists.txt"
        if owned.exists() and text != owned.read_text():
            raise ConanInvalidConfiguration("Modified native CMake input retained")
        if not original.exists():
            if marker in text:
                # Adopt only the exact initial overlay written by this recipe,
                # not arbitrary changes to upstream source/build inputs.
                raw = text.split("\n" + marker, 1)[0]
                raw = load("native_dns").replace_once(
                    raw, 'include("${CMAKE_CURRENT_BINARY_DIR}/native_dns_cloak.cmake")',
                    "include(cloak.cmake)")
                raw = load("native_dns").replace_once(
                    raw, "-I${CMAKE_CURRENT_BINARY_DIR}/native-dns-include\n"
                         "            -I${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client",
                    "-I${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client")
                raw = load("native_dns").replace_once(
                    raw, "${CMAKE_CURRENT_BINARY_DIR}/native-dns-include/client/ovpncli.i)",
                    "${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client/ovpncli.i)")
                original.write_text(raw.rstrip() + "\n")
            else:
                original.write_text(text)
        if original.exists():
            before = text
            text = original.read_text()
            text = load("native_dns").replace_once(
                text, "include(cloak.cmake)",
                'include("${CMAKE_CURRENT_BINARY_DIR}/native_dns_cloak.cmake")')
            text = load("native_dns").replace_once(
                text, "-I${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client",
                "-I${CMAKE_CURRENT_BINARY_DIR}/native-dns-include\n"
                "            -I${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client")
            text = load("native_dns").replace_once(
                text, "${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client/ovpncli.i)",
                "${CMAKE_CURRENT_BINARY_DIR}/native-dns-include/client/ovpncli.i)")
            text += '''
# AMNEZIA_NATIVE_DNS_OVERLAY
target_include_directories(ovpn3 BEFORE PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/native-dns-include")
add_dependencies(ovpn3 ck_ovpn_plugin_go)
file(GLOB_RECURSE _amnezia_dns_headers CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/native-dns-include/*")
# A NEW shadow header is not in an old compiler depfile yet. Explicit owned
# overlay dependencies prevent a successful incremental link of stale code.
set_property(SOURCE openvpn3/client/ovpncli.cpp APPEND PROPERTY
    OBJECT_DEPENDS ${_amnezia_dns_headers})
add_custom_command(OUTPUT "ovpncli_wrap.cxx" APPEND
    DEPENDS ${_amnezia_dns_headers}
        "${CMAKE_CURRENT_SOURCE_DIR}/openvpn3/client/ovpncli.hpp")
'''
            if text != before:
                cmake.write_text(text)
            if not owned.exists() or owned.read_text() != text:
                owned.write_text(text)
        target = build / "native_dns_cloak.cmake"
        data = (support / "native_dns_cloak.cmake").read_bytes()
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)

    def build(self):
        apply_conandata_patches(self)
        self._prepare_dns()
        cmake = CMake(self)
        cmake.configure()
        cmake.build(target=["ck_ovpn_plugin_go", "ovpn3", "ovpnutil", "rsapss"])

    def package(self):
        copy(self, "libck-ovpn-plugin.h", src=self.build_folder,
             dst=os.path.join(self.package_folder, "include"), keep_path=False)
        copy(self, "native_dns.h", src=self.export_sources_folder,
             dst=os.path.join(self.package_folder, "include"), keep_path=False)
        copy(self, "*.so", src=self.build_folder, dst=os.path.join(self.package_folder, "lib"))
        copy(self, "*.java", src=os.path.join(self.build_folder, "ovpn3"),
             dst=os.path.join(self.package_folder, "java", "net", "openvpn", "ovpn3"))
        copy(self, "*", src=os.path.join(self.build_folder, "native-dns-cloak", "native-dns-notices"),
             dst=os.path.join(self.package_folder, "licenses", "cloak"))
        copy(self, "native-cloak-provenance.json",
             src=os.path.join(self.build_folder, "native-dns-cloak", "cmd", "ck-ovpn-plugin"),
             dst=os.path.join(self.package_folder, "licenses", "cloak"))
        copy(self, "native-original-cloak.*", src=os.path.join(self.build_folder, "native-dns-cloak"),
             dst=os.path.join(self.package_folder, "licenses", "cloak", "source"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::openvpn-pt-android")
        self.cpp_info.libs = [ "ovpn3", "ovpnutil", "rsapss" ]
        self.cpp_info.set_property("cmake_extra_variables", {
            "OPENVPN_PT_ANDROID_JAVA_PATH": Path(self.package_folder, "java").as_posix(),
            "OPENVPN_PT_ANDROID_NOTICE_PATH": Path(self.package_folder, "licenses", "cloak").as_posix(),
            "OPENVPN_PT_ANDROID_LIBCK_OVPN_PLUGIN_PATH": Path(self.package_folder, "lib", "libck-ovpn-plugin.so").as_posix()
        })
