from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain, cmake_layout


class ClientWardenConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    def requirements(self):
        self.requires("brotli/[>=1.1.1 <2]", override=True)
        self.requires("botan/3.11.1")
        self.requires("nlohmann_json/3.12.0")
        self.requires("cpp-httplib/0.47.0")
        self.requires("openssl/3.6.3")
        self.requires("boost/1.91.0")
        self.requires("spdlog/1.17.0")
        self.requires("msgpack-cxx/7.0.0")

    def layout(self):
        cmake_layout(self)