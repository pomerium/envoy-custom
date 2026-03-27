load("//bazel:toolchains.bzl", "TOOLCHAIN_INFO", "TOOLCHAIN_INTEGRITY")

def _sysroot_impl(rctx):
    _os_mapping = {
        "linux": "linux",
        "macos": "darwin",
    }
    _arch_mapping = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }
    rctx.download_and_extract(
        sha256 = TOOLCHAIN_INTEGRITY.sysroot["%s-%s" % (_os_mapping[rctx.attr.os], _arch_mapping[rctx.attr.arch])],
        stripPrefix = "%s_%s" % (rctx.attr.os, rctx.attr.arch),
        url = ["{repository}/releases/download/{llvm_version}-{release_revision}/sysroot-{attr_os}-{attr_arch}.tar.zst".format(
            attr_os = rctx.attr.os,
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

sysroot = repository_rule(
    implementation = _sysroot_impl,
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
