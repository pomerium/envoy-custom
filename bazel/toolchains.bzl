load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

LLVM_VERSION = "22.1.1"
LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "1",
}

TOOLCHAIN_INTEGRITY = struct(
    toolchain = {
        "linux-amd64": "29b121ca6ca51a884c0a5d03c730a364785184b6b845f05d647648dfbd78a3a4",
        "linux-aarch64": "ee9c759fddfdd51d34754a0ef3660086138951f038b3d6a2273a7d25b5e6b2da",
        "darwin-aarch64": "d140df515f617bdd473914408ccd15ee421f6d613965f63a41738f22c95015d8",
    },
    sysroot = {
        "linux-amd64": "324d9db1a08fc6de7ef9f94bd540efe731c2c7b89753983c7930306a8fe2d66a",
        "linux-aarch64": "79197a28e96d08cf11f02e8d4ad681bedd33955be8b4169fc9c549c4548b6146",
    },
    cxx_cross_libs = {
        "linux-aarch64": "4ccbdd12777f7c8611dfb6b4347d5a7976e7a403595eed3f47ca7ec31f543cf9",
        "darwin-aarch64": "fefa98978f5d79119307feeda4f613624e6b831f827a0386269851e923dc8928",
    },
)

def pomerium_envoy_toolchains():
    arch_alias(
        name = "clang_platform",
        aliases = {
            "amd64": "@//bazel/platforms/rbe:linux_x64",
            "aarch64": "@//bazel/platforms/rbe:linux_arm64",
        },
    )
    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = LLVM_VERSION,
        cxx_standard = {"": "c++23"},
        sysroot = {
            "linux-x86_64": "@minimal_sysroot_linux_amd64//:sysroot",
            "linux-aarch64": "@minimal_sysroot_linux_arm64//:sysroot",
            "darwin-aarch64": "@macos_sysroot//:sysroot",
        },
        cxx_cross_lib = {
            "linux-aarch64": "@cxx_cross_libs_linux_arm64//:cxx_cross_libs",
            "darwin-aarch64": "@cxx_cross_libs_darwin_arm64//:cxx_cross_libs",
        },
        libclang_rt = {
            "@cxx_cross_libs_linux_arm64//:lib/libclang_rt.builtins.a": "aarch64-unknown-linux-gnu/libclang_rt.builtins.a",
            "@cxx_cross_libs_linux_arm64//:lib/clang_rt.crtbegin.o": "aarch64-unknown-linux-gnu/clang_rt.crtbegin.o",
            "@cxx_cross_libs_linux_arm64//:lib/clang_rt.crtend.o": "aarch64-unknown-linux-gnu/clang_rt.crtend.o",
            "@cxx_cross_libs_darwin_arm64//:lib/libclang_rt.osx.a": "aarch64-apple-macosx/libclang_rt.osx.a",
        },
        extra_link_flags = {
            "linux-x86_64": ["-rtlib=compiler-rt", "-l:libunwind.a"],
            "linux-aarch64": ["-rtlib=compiler-rt", "-l:libunwind.a"],
            "darwin-aarch64": ["-rtlib=compiler-rt"],
        },
        urls = {
            "linux-x86_64": ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-{llvm_version}-minimal-linux-amd64.tar.zst".format(**TOOLCHAIN_INFO)],
            "linux-aarch64": ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-{llvm_version}-minimal-linux-arm64.tar.zst".format(**TOOLCHAIN_INFO)],
            "darwin-aarch64": ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-{llvm_version}-minimal-macos-arm64.tar.zst".format(**TOOLCHAIN_INFO)],
        },
        strip_prefix = {
            "linux-x86_64": "llvm-{llvm_version}-minimal-linux-amd64".format(**TOOLCHAIN_INFO),
            "linux-aarch64": "llvm-{llvm_version}-minimal-linux-arm64".format(**TOOLCHAIN_INFO),
            "darwin-aarch64": "llvm-{llvm_version}-minimal-macos-arm64".format(**TOOLCHAIN_INFO),
        },
        sha256 = TOOLCHAIN_INTEGRITY.toolchain,
        toolchain_roots = {"": LLVM_PATH} if LLVM_PATH else {},  # for RBE container image
        # TODO: this file is missing in the macos release tarball
        extra_compiler_files = None if LLVM_PATH else "@llvm_toolchain_llvm//:lib/clang/%s/share/msan_ignorelist.txt" % LLVM_MAJOR_VERSION,
        # Include directory to find msan_ignorelist.txt
        cxx_builtin_include_directories = {
            "linux-x86_64": ["%workspace%" + "/%s/lib/clang/%s/share" % (LLVM_PATH if LLVM_PATH else "external/llvm_toolchain_llvm", LLVM_MAJOR_VERSION)],
            "linux-aarch64": ["%workspace%" + "/%s/lib/clang/%s/share" % (LLVM_PATH if LLVM_PATH else "external/llvm_toolchain_llvm", LLVM_MAJOR_VERSION)],
            "darwin-aarch64": ["%workspace%" + "/%s/lib/clang/%s/share" % (LLVM_PATH if LLVM_PATH else "external/llvm_toolchain_llvm", LLVM_MAJOR_VERSION)],
        },
    )
