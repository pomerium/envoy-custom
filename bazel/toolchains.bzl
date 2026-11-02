load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

LLVM_VERSION = "23.1.4"
LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "1",
}

TOOLCHAIN_INTEGRITY = struct(
    cxx_cross_libs = {
        "linux-aarch64": "11df0b48da5aad0f56d7fa45f13c5271b1580c5b6606d957059775634ebb9a27",
        "darwin-aarch64": "f7904d1925453e5a3258db460b6026697987d850deeb207148b9e96f53108d33",
    },
    toolchain = {
        "linux-x86_64": "fcb5c1da85ed5cd7f4a97f20aa76f850dccca9da5ef7d1259de0c98547975008",
        "linux-aarch64": "0004834464a39816442af59bfadffb85282f33da256e7300d742a53b8da42080",
        "darwin-aarch64": "689dc95f3195752f95dc14414a6554c0a6a406f1e2c70097abfd85480e2daeba",
    },
    extras = {
        "linux-x86_64": "cedee7d604081a0916ddcafaf1d7da3e0abce2bd66e1f85cb0e4e77bc444be93",
        "linux-aarch64": "681a7b796a4635e8a1cc3c03dcedf6c8a8cbeb2567cee6b205e7d1264960b391",
    },
    macos_utils = {
        "linux-x86_64": "4ed2bd512ed47384f1687324d1d56f38de63437171bd64c790b0a04306cb0e37",
        "linux-aarch64": "c5849656682bc063a04af4620d511d998ced0928e8501932d2dcbcc15ec9f3ce",
        "darwin-aarch64": "7c95d85b4088078c7e04cf33d23afe8d1fac885b38eeba8cd2dd9f600f3045ce",
    },
    sysroot = {
        "linux-x86_64": "27497271a3bebf1e4b75c5852ec54229c90442f4d3fcd012319df43aa26d7a0b",
        "linux-aarch64": "0b451d1dfa7fdba02033ce008b4cb2da2bbecfb0314e67a0d61add7b62f25447",
        "darwin-aarch64": "6becf9c7dfd155d18352ee3fb5f527c6246be90929b3fb7d29af71bc9e1227ee",
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
        extra_cxx_flags = {
            # The current versions of abseil and tcmalloc use deprecated builtin attributes.
            # These flags can be removed when tcmalloc is updated to use abseil >= 20260817.0
            "linux-x86_64": ["-Wno-deprecated-attributes", "-Wno-deprecated-builtins", "-Wno-attribute-alias"],
            "linux-aarch64": ["-Wno-deprecated-attributes", "-Wno-deprecated-builtins", "-Wno-attribute-alias"],
            "darwin-aarch64": ["-Wno-deprecated-attributes", "-Wno-deprecated-builtins", "-Wno-attribute-alias"],
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
    )
