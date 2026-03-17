load("//bazel:toolchains.bzl", "TOOLCHAIN_INFO", "TOOLCHAIN_INTEGRITY")

def _cxx_cross_libs_impl(rctx):
    _os_mapping = {
        "linux": "linux",
        "macos": "darwin",
    }
    _arch_mapping = {
        "amd64": "amd64",
        "arm64": "aarch64",
    }
    rctx.download_and_extract(
        sha256 = TOOLCHAIN_INTEGRITY.cxx_cross_libs["%s-%s" % (_os_mapping[rctx.attr.os], _arch_mapping[rctx.attr.arch])],
        url = ["{repository}/releases/download/{llvm_version}-{release_revision}/cxx-cross-libs-{llvm_version}-{attr_os}-{attr_arch}.tar.zst".format(
            attr_os = rctx.attr.os,
            attr_arch = rctx.attr.arch,
            **TOOLCHAIN_INFO
        )],
    )
    prefix = "cxx-cross-libs-{llvm_version}-{attr_os}-{attr_arch}".format(
        attr_os = rctx.attr.os,
        attr_arch = rctx.attr.arch,
        **TOOLCHAIN_INFO
    )
    rctx.execute(["mkdir", "lib"])
    rctx.execute(["mkdir", "include"])
    rctx.execute(["find", "%s/include" % prefix, "-type", "f", "-exec", "mv", "{}", "include/", ";"])
    rctx.execute(["find", "%s/lib" % prefix, "-type", "f", "-exec", "mv", "{}", "lib/", ";"])
    rctx.delete(prefix)

    rctx.file("BUILD", """
filegroup(
    name = "cxx_cross_libs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
""")

cxx_cross_libs = repository_rule(
    implementation = _cxx_cross_libs_impl,
    attrs = {
        "os": attr.string(
            mandatory = True,
            values = ["linux", "macos"],
        ),
        "arch": attr.string(
            default = "arm64",
            values = ["arm64"],
        ),
    },
)
