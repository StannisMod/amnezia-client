from conan import ConanFile
from conan.tools.layout import basic_layout
from conan.tools.scm import Git
from conan.tools.files import copy, collect_libs
from conan.internal.model.pkg_type import PackageType
from conan.tools.gnu import AutotoolsToolchain, Autotools
from conan.tools.apple import is_apple_os

import os
import shutil
import importlib.util
import io
from pathlib import Path


required_conan_version = ">=2.26"


class HevSocks5Tunnel(ConanFile):
    name = "hev-socks5-tunnel"
    version = "2.15.0"
    exports = "native_dns_filter.py"
    settings = "os", "arch", "compiler"
    options = {
        "shared": [True, False],
        "as_framework": [True, False],
    }
    default_options = {
        "shared": False,
        "as_framework": False
    }

    def config_options(self):
        if not is_apple_os(self):
            del self.options.as_framework

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")
        if self.options.get_safe("as_framework"):
            self.options.shared = False

    def layout(self):
        basic_layout(self, build_folder=".")

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/heiher/hev-socks5-tunnel.git",
            target=".",
            args=["--recurse-submodules", "--branch", self.version]
        )

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.generate()

    def build(self):
        if self.options.get_safe("as_framework"):
            helper = Path(self.recipe_folder, "native_dns_filter.py")
            spec = importlib.util.spec_from_file_location("amnezia_hev_native_dns", helper)
            overlay = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(overlay)
            source = Path(self.build_folder, "src", "hev-socks5-tunnel.c")
            source.write_text(overlay.prepare(source.read_text()))
            header = Path(self.build_folder, "src", "hev-main.h")
            header.write_text(overlay.prepare_header(header.read_text()))
        autotools = Autotools(self)
        autotools.make("shared" if self.options.shared else "static")

        if self.options.get_safe("as_framework"):
            lib_path = os.path.join(self.build_folder, "bin", "libhev-socks5-tunnel.a")
            symbols = io.StringIO()
            self.run(f'nm -g "{lib_path}"', stdout=symbols)
            entries = {tuple(line.split()[-2:]) for line in symbols.getvalue().splitlines()}
            for callback in ("_AmneziaNativePacketFilterFeed", "_amnezia_hev_ready"):
                if ("U", callback) not in entries:
                    raise RuntimeError(f"Apple HEV archive is missing required native callback {callback}")
            if ("T", "_amnezia_hev_filter_enable") not in entries:
                raise RuntimeError("Apple HEV archive is missing native filter activation")
            self.run(
                f"libtool -static -o {lib_path}"
                f" {lib_path}"
                f" {os.path.join(self.build_folder, 'third-part', 'lwip', 'bin', 'liblwip.a')}"
                f" {os.path.join(self.build_folder, 'third-part', 'yaml', 'bin', 'libyaml.a')}"
                f" {os.path.join(self.build_folder, 'third-part', 'hev-task-system', 'bin', 'libhev-task-system.a')}"
            )

            include_dir = os.path.join(self.build_folder, "framework_include")
            copy(self, "hev-main.h", src=os.path.join(self.source_folder, "src"), dst=include_dir)
            copy(self, "module.modulemap", src=os.path.join(self.source_folder), dst=include_dir)

            self.run('xcodebuild -create-xcframework'
                f' -library {lib_path}'
                f' -headers {include_dir}'
                f' -output {os.path.join(self.build_folder, "HevSocks5Tunnel.xcframework")}'
            )

    def package(self):
        if self.options.get_safe("as_framework"):
            shutil.copytree(src=os.path.join(self.build_folder, "HevSocks5Tunnel.xcframework"),
                            dst=os.path.join(self.package_folder, "HevSocks5Tunnel.xcframework"))
        else:
            copy(self, "hev-main.h", src=os.path.join(self.source_folder, "src"), dst=os.path.join(self.package_folder, "include"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "lwip"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "lwip"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "yaml"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "yaml"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "hev-task-system"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "hev-task-system"), dst=os.path.join(self.package_folder, "lib"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "heiher::hev-socks5-tunnel")
        if self.options.get_safe("as_framework"):
            self.cpp_info.type = PackageType.STATIC
            self.cpp_info.package_framework = True
            self.cpp_info.location = os.path.join(self.package_folder, "HevSocks5Tunnel.xcframework")
        else:
            self.cpp_info.libraries = collect_libs(self)
