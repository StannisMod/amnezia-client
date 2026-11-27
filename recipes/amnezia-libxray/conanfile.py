from conan import ConanFile
from conan.tools.files import get, copy, apply_conandata_patches, export_conandata_patches
from conan.tools.layout import basic_layout
from conan.errors import ConanInvalidConfiguration
from conan.tools.env import Environment

import os
import stat
import importlib.util
import io

from pathlib import Path

class AmneziaLibxray(ConanFile):
    name = "amnezia-libxray"
    version = "1.0.3"
    settings = "os", "arch", "compiler"

    def export_sources(self):
        export_conandata_patches(self)
        copy(self, "native_dns.py", self.recipe_folder, self.export_sources_folder)
        copy(self, "native_dns_android.go", self.recipe_folder, self.export_sources_folder)
        copy(self, "native_dns_android_test.go", self.recipe_folder, self.export_sources_folder)
        copy(self, "native_dns_socks_test.go", self.recipe_folder, self.export_sources_folder)
        root = Path(self.recipe_folder).parents[1] / "native" / "routing" / "nativedns"
        copy(self, "*.go", str(root), str(Path(self.export_sources_folder) / "nativedns"))

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        basic_layout(self, build_folder=".")

    def build_requirements(self):
        self.tool_requires("go/1.27.1")
    
    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        get(self, f"https://github.com/amnezia-vpn/amnezia-libxray/archive/refs/tags/v{self.version}.zip",
            sha256="3b1194c2a76e73913fdae49983c40a219c45a164ebdae72ef1297469348de730", strip_root=True
        )

    def generate(self):
        env = Environment()
        ndk_path_str = self.conf.get("tools.android:ndk_path")
        if ndk_path_str:
            ndk_path = Path(ndk_path_str)
            if len(ndk_path.parts) > 2:
                sdk_path = ndk_path.parents[1]
                env.define("ANDROID_HOME", str(sdk_path))
        env.vars(self).save_script("conan_provide_androidhome")

    def _patch_sources(self):
        apply_conandata_patches(self)
        module = io.StringIO()
        self.run('go list -mod=readonly -m -f "{{.Dir}}" github.com/amnezia-vpn/amnezia-tun2socks/v2',
                 cwd=self.build_folder, stdout=module)
        dependency = Path(module.getvalue().strip())
        if not dependency.is_dir():
            raise ConanInvalidConfiguration("Existing native tun2socks source is unavailable")
        overlay_path = Path(self.export_sources_folder) / "native_dns.py"
        spec = importlib.util.spec_from_file_location("android_xray_native_dns", overlay_path)
        overlay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(overlay)
        overlay.apply(self.build_folder, dependency, self.export_sources_folder,
                      Path(self.export_sources_folder) / "nativedns")
        build_path = os.path.join(self.build_folder, "build.sh")
        # Resolve the pinned graph, never rewrite requirements/sums via tidy.
        replace = Path(build_path).read_text()
        if replace.count("    go mod tidy") != 1:
            raise ConanInvalidConfiguration("Native libXray dependency preparation changed")
        Path(build_path).write_text(replace.replace(
            "    go mod tidy", "    go list -mod=readonly -m all >/dev/null", 1))
        build_stat = os.stat(build_path)
        os.chmod(build_path, build_stat.st_mode | stat.S_IEXEC)

    def build(self):
        self._patch_sources()
        if self.settings_build.os == "Windows":
            self.run("bash build.sh android")
        else:
            self.run("./build.sh android")

    def package(self):
        copy(self, "libxray.aar", src=self.build_folder, dst=os.path.join(self.package_folder, "aar"))

    def package_info(self):
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_LIBXRAY_PATH": Path(self.package_folder, "aar", "libxray.aar").as_posix(),
        })
