from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.env import VirtualBuildEnv

required_conan_version = ">=2.0.1"


class ACMEClientLibrary(ConanFile):
    settings = "os", "arch", "compiler", "build_type"

    def configure(self):
        self.options['libcurl/*'].with_ssl = "openssl"

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("openssl/1.1.1t")
        self.requires("boost/1.81.0")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

        tc = CMakeDeps(self)
        tc.generate()

        tc = VirtualBuildEnv(self)
        tc.generate()
