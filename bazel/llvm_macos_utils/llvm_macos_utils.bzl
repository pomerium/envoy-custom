load("//bazel:toolchains.bzl", "TOOLCHAIN_INFO", "TOOLCHAIN_INTEGRITY")

def _llvm_macos_utils_impl(rctx):
    _os_mapping = {
        "linux": "linux",
        "macos": "darwin",
    }
    _arch_mapping = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }
    rctx.download_and_extract(
        sha256 = TOOLCHAIN_INTEGRITY.macos_utils["%s-%s" % (_os_mapping[rctx.attr.os], _arch_mapping[rctx.attr.arch])],
        stripPrefix = "llvm-macos-utils-{llvm_version}-{attr_os}-{attr_arch}".format(
            attr_os = rctx.attr.os,
            attr_arch = rctx.attr.arch,
            **TOOLCHAIN_INFO
        ),
        url = ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-macos-utils-{llvm_version}-{attr_os}-{attr_arch}.tar.zst".format(
            attr_os = rctx.attr.os,
            attr_arch = rctx.attr.arch,
            **TOOLCHAIN_INFO
        )],
    )
    rctx.file("BUILD", """
filegroup(
    name = "llvm_macos_utils",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
""")

llvm_macos_utils = repository_rule(
    implementation = _llvm_macos_utils_impl,
    attrs = {
        "os": attr.string(
            mandatory = True,
            values = ["linux", "macos"],
        ),
        "arch": attr.string(
            mandatory = True,
            values = ["amd64", "arm64"],
        ),
    },
)
