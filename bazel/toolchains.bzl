load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

LLVM_VERSION = "22.1.4"
LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "0",
}

TOOLCHAIN_INTEGRITY = struct(
    cxx_cross_libs = {
        "linux-aarch64": "1266df9af6ed4feb75d02abf05279f3c140cde9ff377f50ab5cecbc3b04e4006",
        "darwin-aarch64": "e11482ca4b7d5a782152cd86a4c881a2c836d541568c997f81dab0ad81f90417",
    },
    toolchain = {
        "linux-x86_64": "758d0302e51c93e2882d45dfc10c2d4b9731ce5a03f8d565d03cca6ad33060db",
        "linux-aarch64": "9b4de299282bdbe1faefd0d7e7daebee6d8bfded365c28942c7aced752876035",
        "darwin-aarch64": "f37d164e6d792ba49cf616fd9bb2b1bf2ca9a11b300b752cc4a43a37c7f0cf58",
    },
    extras = {
        "linux-x86_64": "f2c7d1d00e1e2dd128bbd943152dab331d60a5dfd066eeaa59d9b87958e6492f",
        "linux-aarch64": "13e1622bafc902508e56b7ac2252b61046e27f04a378cf43aa63bbd42351950e",
    },
    sysroot = {
        "linux-x86_64": "60d503a72a3728a0e3fee8c8bda0f9dab23251f0225c7f0c6aafd8993d4122cb",
        "linux-aarch64": "b9b7e53597c6b7b3289960ad16d6dd01763b9d6ab6122e7c74b72c6823a355b3",
        "darwin-aarch64": "66d832c60d90af0248abff0c6c4ea95a52795ce367608f199e24262676ee6b93",
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
