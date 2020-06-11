import os
import fnmatch
from conans import ConanFile, AutoToolsBuildEnvironment, tools

class MeshlinklibConan(ConanFile):
    name = "meshlink"
    version = "0.2.7"
    license = "<Put the package license here>"
    author = "<Put your name here> <And your email here>"
    url = "https://github.com/elear-solutions/meshlink"
    description = "This recipe file used to build and package binaries of meshlink repository"
    topics = ("peer-to-peer", "networking", "p2p")
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False]
    }
    default_options = {key: False for key in options.keys()}
    default_options ["shared"] = False
    generators = "make"

    @property
    def _targets(self):
        return {
            "iOS-x86-*": "i386-apple-ios",
            "iOS-x86_64-*": "x86_64-apple-ios"
        }
    def config_options(self):
        args = ["--prefix=${PWD}"]
        return args

    def build(self):
        autotools = AutoToolsBuildEnvironment(self)
        args = self.config_options()
        self.run("cd .. && autoreconf -fsi ")
        query = "%s-%s-%s" % (self.settings.os, self.settings.arch, self.settings.compiler)
        ancestor = next((self._targets[i] for i in self._targets if fnmatch.fnmatch(query, i)), None)
        if not ancestor:
            autotools.configure(configure_dir= "..",args= args, use_default_install_dirs=True)
        else:
            autotools.configure(configure_dir= "..",args= args, use_default_install_dirs=True, host= ancestor)
        autotools.make()
        autotools.install()

    def package(self):
        self.copy("*.h", dst="include", src="src/include/")
        self.copy("*.h", dst="include", src="catta/include/include")
        # By default, files are copied recursively. To avoid that we are specifying keep_path=False
        self.copy("*", dst="lib", src="src/lib", keep_path=False)
        self.copy("*", dst="lib", src="catta/src/lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = [ "meshlink" , "catta"]
