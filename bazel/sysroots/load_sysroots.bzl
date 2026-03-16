load("//bazel/sysroots:linux.bzl", "linux_sysroot")
load("//bazel/sysroots:macos.bzl", "macos_sysroot")

def load_sysroots():
    linux_sysroot(
        name = "minimal_sysroot_linux_amd64",
        arch = "amd64",
    )

    linux_sysroot(
        name = "minimal_sysroot_linux_arm64",
        arch = "arm64",
    )

    macos_sysroot(
        name = "macos_sysroot",
    )
