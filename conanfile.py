from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.env import VirtualBuildEnv

required_conan_version = ">=2.21.0"


class PKITool(ConanFile):
    settings = "os", "arch", "compiler", "build_type"

    def configure(self):
        self.options['libcurl/*'].with_ssl = "openssl"

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("openssl/3.4.5")
        self.requires("boost/1.88.0")
        self.requires("gtest/1.14.0")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

        tc = CMakeDeps(self)
        tc.generate()

        tc = VirtualBuildEnv(self)
        tc.generate()
