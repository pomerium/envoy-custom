load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

LLVM_VERSION = "22.1.3"
LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "0",
}

TOOLCHAIN_INTEGRITY = struct(
    cxx_cross_libs = {
        "linux-aarch64": "c187edb7412a5ee79bdcabab936d367c43db2ce41e0e449f2d08a13efb24880c",
        "darwin-aarch64": "7284418b0331f86482788547818819148775c779e6bb53ec4914d7ebb36d1bab",
    },
    toolchain = {
        "linux-x86_64": "f3a7549729f7c05df11c5b7f7eafba227ea3c6ca498af6e1cd8bda6132a56d78",
        "linux-aarch64": "917a3a7e744f2d911ff371e465aae86d9af6f434f0d942238c17212f3fd4d3a4",
        "darwin-aarch64": "d5fbdf180c58e54b69c09ccb78b4576465b6b8740920154c9944113b887bac73",
    },
    extras = {
        "linux-x86_64": "2b03539ef789e12b9d77a3e76d497562f1df7847167e13744e13ad7592770c46",
        "linux-aarch64": "2b2aaa348047c10d1cdcdbc189b8934188009355e1decd90de5608d102c98548",
    },
    sysroot = {
        "linux-x86_64": "34b391fa4e41e2f9e8cecc91ee9b645014b91ffcc0ab638f5276eef4cba1bdf9",
        "linux-aarch64": "e2944bc3600a26ca9890817408d9023583e4d876837e13ce6fc774fe8a65e252",
        "darwin-aarch64": "97aa7d2af83e8e12e153dd4ef12d65e02ad30cf9ae94f195db67ec9bbb7c8051",
    },
)

def pomerium_envoy_toolchains():
    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = LLVM_VERSION,
        cxx_standard = {"": "c++23"},
        sysroot = {
            "linux-x86_64": "@minimal_sysroot_linux_amd64//:sysroot",
            "linux-aarch64": "@minimal_sysroot_linux_arm64//:sysroot",
            "darwin-aarch64": "@minimal_sysroot_macos_arm64//:sysroot",
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
