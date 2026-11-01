from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import get, copy, collect_libs, chdir
from conan.tools.apple import is_apple_os
from conan.tools.gnu import AutotoolsToolchain, Autotools

import os
import shutil
import importlib.util

class AwgApple(ConanFile):
    name = "awg-apple"
    version = "3.1.4-routing.2"
    _upstream_version = "3.1.4"
    settings = "os", "arch", "compiler"

    @property
    def _goarch(self):
        arch_map = {
            "armv8": "arm64",
            "x86_64": "x86_64",
        }
        archs = str(self.settings.arch).split("|")
        return " ".join(arch_map.get(arch, arch) for arch in archs)

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        basic_layout(self, build_folder=os.path.join(self.folders.source, "Sources/WireGuardKitGo"))

    def build_requirements(self):
        self.tool_requires("go/1.27.1")

    def validate(self):
        if not is_apple_os(self):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os}"
            )

    def source(self):
        get(self, f"https://github.com/amnezia-vpn/amneziawg-apple/archive/refs/tags/v{self._upstream_version}.zip",
            sha256="09d7b760d18232fdf121ed2286b2f171b501dc31137e5e7d557c1ee3a99ef772", strip_root=True,
            destination=os.path.join(self.source_folder, "upstream")
        )

    def export_sources(self):
        copy(self, "*", src=os.path.join(self.recipe_folder, "..", "..", "native", "routing"),
             dst=os.path.join(self.export_sources_folder, "routing-core"),
             excludes=["**/__pycache__/*", "**/*.pyc"])

    def generate(self):
        tc = AutotoolsToolchain(self)
        sdk = self.settings.get_safe("os.sdk", "macosx")
        tc.make_args = [
            f"ARCHS={self._goarch}",
            f"PLATFORM_NAME={sdk}"
        ]
        tc.generate()

    def build(self):
        module = os.path.join(self.build_folder, "module")
        shutil.copytree(os.path.join(self.source_folder, "upstream", "Sources", "WireGuardKitGo"),
                        module, dirs_exist_ok=True, symlinks=True)
        core = os.path.join(self.source_folder, "routing-core")
        spec = importlib.util.spec_from_file_location("amnezia_prepare_apple", os.path.join(core, "prepare_apple.py"))
        prepare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prepare)
        prepare.prepare_module(core, module)
        autotools = Autotools(self)
        with chdir(self, module):
            autotools.make()
            autotools.make("version-header")

        notice_spec = importlib.util.spec_from_file_location("amnezia_routing_notices", os.path.join(core, "licenses", "generate.py"))
        notices = importlib.util.module_from_spec(notice_spec)
        notice_spec.loader.exec_module(notices)
        notices.generate(module, os.path.join(self.build_folder, "routing-licenses"), host_root=os.path.join(self.source_folder, "upstream"))

    def package(self):
        module = os.path.join(self.build_folder, "module")
        copy(self, "wireguard.h", src=module, dst=os.path.join(self.package_folder, "include"))
        copy(self, "amnezia_routing.h", src=module, dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.h", src=os.path.join(module, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.a", src=os.path.join(module, "out"), dst=os.path.join(self.package_folder, "lib"))

        copy(self, "*", src=os.path.join(self.build_folder, "routing-licenses"), dst=os.path.join(self.package_folder, "licenses", "routing"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-apple")
        self.cpp_info.libs = collect_libs(self)
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_ROUTING_LICENSE_DIR": os.path.join(self.package_folder, "licenses", "routing").replace(os.sep, "/"),
        })
