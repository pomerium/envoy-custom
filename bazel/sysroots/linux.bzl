load("//bazel:toolchains.bzl", "TOOLCHAIN_INFO", "TOOLCHAIN_INTEGRITY")

def _linux_sysroot_impl(rctx):
    _arch_mapping = {
        "amd64": "amd64",
        "arm64": "aarch64",
    }
    rctx.download_and_extract(
        sha256 = TOOLCHAIN_INTEGRITY.sysroot["linux-%s" % _arch_mapping[rctx.attr.arch]],
        stripPrefix = "linux_%s" % rctx.attr.arch,
        url = ["{repository}/releases/download/{llvm_version}-{release_revision}/sysroot-linux-{attr_arch}.tar.zst".format(
            attr_arch = rctx.attr.arch,
            **TOOLCHAIN_INFO
        )],
    )
    rctx.file("BUILD", """
filegroup(
    name = "sysroot",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
""")

linux_sysroot = repository_rule(
    implementation = _linux_sysroot_impl,
    attrs = {
        "arch": attr.string(
            mandatory = True,
            values = ["amd64", "arm64"],
        ),
    },
)
