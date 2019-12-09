from conans import ConanFile, AutoToolsBuildEnvironment, tools

class MeshlinklibConan(ConanFile):
    name = "meshlink"
    license = "<Put the package license here>"
    author = "<Put your name here> <And your email here>"
    url = "<Package recipe repository url here, for issues about the package>"
    description = "This recipe file used to build and package binaries of meshlink repository"
    topics = ("<Put some tag here>", "<here>", "<and here>")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}
    default_options = "shared=False"
    generators = "make"

    def build(self):
        autotools = AutoToolsBuildEnvironment(self)
        self.run("cd .. && autoreconf -fsi")
        autotools.configure(configure_dir="..", args=["--prefix=${PWD}"])
        # This is a temporary fix for the error - "Error 512 while executing make -j1".
        # Once the issue is resolved in the meshlink's build process, this will be removed.
        self.run("cd ../doc && sed -e s,'@PACKAGE\@',\"meshlink\",g -e s,'@VERSION\@',\"0.1\","
        "g -e s,'@sysconfdir\@',\"/usr/local/etc\",g -e s,'@localstatedir\@',\"/usr/local/var\","
        "g include.texi.in > include.texi")
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
