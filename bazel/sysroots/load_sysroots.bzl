load("//bazel/sysroots:sysroot.bzl", "sysroot")

def load_sysroots():
    sysroot(
        os = "linux",
        name = "minimal_sysroot_linux_amd64",
        arch = "amd64",
    )

    sysroot(
        os = "linux",
        name = "minimal_sysroot_linux_arm64",
        arch = "arm64",
    )

    sysroot(
        os = "macos",
        name = "minimal_sysroot_macos_arm64",
        arch = "arm64",
    )
