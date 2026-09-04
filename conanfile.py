from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain, cmake_layout


class ClientWardenConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    def requirements(self):
        if self.settings.os != "Android":
            self.requires("qt/6.11.1")
        if self.settings.os == "Android":
            self.requires("jthread-lite/0.1.0")
        self.requires("botan/3.11.1")
        self.requires("nlohmann_json/3.12.0")
        self.requires("cpp-httplib/0.47.0")
        self.requires("openssl/3.6.3")
        self.requires("boost/1.91.0")
        self.requires("spdlog/1.17.0")
        self.requires("msgpack-cxx/7.0.0")

    def configure(self):
        if self.settings.os != "Android":
            self.options["qt/*"].shared = True
            self.options["qt/*"].qtdeclarative = True
            self.options["qt/*"].with_pq = False
            self.options["qt/*"].qtshadertools = True

    def layout(self):
        cmake_layout(self)