load("@aspect_bazel_lib//lib:repo_utils.bzl", "repo_utils")
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
    rctx.execute(["find", "%s/lib" % prefix, "-type", "f,l", "-exec", "mv", "{}", "lib/", ";"])

    if rctx.attr.os == "macos":
        host_install_name_tool = Label("@llvm_macos_utils_%s//:bin/llvm-install-name-tool" % repo_utils.platform(rctx))

        # Patch the libc++ and libc++abi dylibs such that binaries linking against these will
        # look in /usr/lib/ for the system libraries, instead of @rpath/
        res = rctx.execute([
            str(rctx.path(host_install_name_tool)),
            "-id",
            "/usr/lib/libc++.1.dylib",
            "lib/libc++.1.dylib",
        ])
        if res.return_code != 0:
            fail("install_name_tool failed: %s" % res.stderr)

        # By default the ID for libc++abi is @rpath/libc++abi.1.dylib. /usr/lib/libc++abi.1.dylib
        # may not exist however, so use /usr/lib/libc++abi.dylib instead
        res = rctx.execute([
            str(rctx.path(host_install_name_tool)),
            "-id",
            "/usr/lib/libc++abi.dylib",
            "lib/libc++abi.1.0.dylib",
        ])
        if res.return_code != 0:
            fail("install_name_tool failed: %s" % res.stderr)

        res = rctx.execute([
            "sed",
            "-i",
            "s/#define _LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS 0/#define _LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS 1/",
            "include/__config_site",
        ])
        if res.return_code != 0:
            fail("sed failed: %s" % res.stderr)

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
