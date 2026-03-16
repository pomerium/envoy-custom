load("//bazel/cxx_libs:cxx_cross_libs.bzl", "cxx_cross_libs")

def load_cxx_cross_libs():
    cxx_cross_libs(
        name = "cxx_cross_libs_linux_arm64",
        os = "linux",
        arch = "arm64",
    )

    cxx_cross_libs(
        name = "cxx_cross_libs_darwin_arm64",
        os = "macos",
        arch = "arm64",
    )
