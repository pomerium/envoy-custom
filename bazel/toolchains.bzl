# load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

LLVM_VERSION = "23.1.4"
LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "2",
}

TOOLCHAIN_INTEGRITY = {
    "cxx_cross_libs": {
        "linux-aarch64": "8fe9339fe1c6cbead72e5b0d8cf03ea89ac78bd1e0c780ee65168057867694f6",
        "darwin-aarch64": "0971a1ced076f696b1d93eae3baee2cfa765f7896278282860615030c9a2ff5a",
    },
    "toolchain": {
        "linux-x86_64": "b5f532efed9cb2f30bd7fe76adba4eb20c71921d0987d11f2dcf12312ee03195",
        "linux-aarch64": "2486fb116adba522a89be32483b3aac35a23f42ef468db3ffb54eac5d85a5e04",
        "darwin-aarch64": "89f38b6e282d9dda6b32c050616233837d498c46054b7badaa54446e8985549c",
    },
    "extras": {
        "linux-x86_64": "deb766c65bfebce41e848cb876006999f06e3416b23b67abe9a4d5bf30cccc10",
        "linux-aarch64": "91c9ce4f7d679255d42ffe77adb7aa3569f0e391974ee464884690c410a2d194",
    },
    "macos_utils": {
        "linux-x86_64": "8922cc80a8938d21484ef2faebf51b8b9ab9e594f288a0ce51f4c5f1115c8d37",
        "linux-aarch64": "73dd0b5a4cf7ef1ba8c62da7662d13f66122e4914ed375d27c699476875a6ff7",
        "darwin-aarch64": "1290297e46af25578e9203d59ddcdf8ac423b43389c0d28bb1c1daff6ca46177",
    },
    "sysroot": {
        "linux-x86_64": "fcfd031a708fed68ded961b4258becf0577c10157a04df8ef5850a8f1e43a794",
        "linux-aarch64": "43064f795f37c56bb35675d50f7165eabfe0a22ac0114a4870b2440519f75e2c",
        "darwin-aarch64": "80247f369ccbbd83cd48a87f270b79cddebcfe555447cccd610a7a2bf2e694f7",
    },
}

# def pomerium_envoy_toolchains():
#     llvm_toolchain(
#         name = "llvm_toolchain",
#         llvm_version = LLVM_VERSION,
#         cxx_standard = {"": "c++23"},
#         sysroot = {
#             "linux-x86_64": "@minimal_sysroot_linux_amd64//:sysroot",
#             "linux-aarch64": "@minimal_sysroot_linux_arm64//:sysroot",
#             "darwin-aarch64": "@minimal_sysroot_macos_arm64//:sysroot",
#         },
#         cxx_cross_lib = {
#             "linux-aarch64": "@cxx_cross_libs_linux_arm64//:cxx_cross_libs",
#             "darwin-aarch64": "@cxx_cross_libs_darwin_arm64//:cxx_cross_libs",
#         },
#         libclang_rt = {
#             "@cxx_cross_libs_linux_arm64//:lib/libclang_rt.builtins.a": "aarch64-unknown-linux-gnu/libclang_rt.builtins.a",
#             "@cxx_cross_libs_linux_arm64//:lib/clang_rt.crtbegin.o": "aarch64-unknown-linux-gnu/clang_rt.crtbegin.o",
#             "@cxx_cross_libs_linux_arm64//:lib/clang_rt.crtend.o": "aarch64-unknown-linux-gnu/clang_rt.crtend.o",
#             "@cxx_cross_libs_darwin_arm64//:lib/libclang_rt.osx.a": "aarch64-apple-macosx/libclang_rt.osx.a",
#         },
#         extra_link_flags = {
#             "linux-x86_64": ["-rtlib=compiler-rt", "-l:libunwind.a"],
#             "linux-aarch64": ["-rtlib=compiler-rt", "-l:libunwind.a"],
#             "darwin-aarch64": ["-rtlib=compiler-rt"],
#         },
#         extra_cxx_flags = {
#             # The current versions of abseil and tcmalloc use deprecated builtin attributes.
#             # These flags can be removed when tcmalloc is updated to use abseil >= 20260817.0
#             "linux-x86_64": ["-Wno-deprecated-attributes", "-Wno-deprecated-builtins", "-Wno-attribute-alias"],
#             "linux-aarch64": ["-Wno-deprecated-attributes", "-Wno-deprecated-builtins", "-Wno-attribute-alias"],
#             "darwin-aarch64": ["-Wno-deprecated-attributes", "-Wno-deprecated-builtins", "-Wno-attribute-alias"],
#         },
#         urls = {
#             "linux-x86_64": ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-{llvm_version}-minimal-linux-amd64.tar.zst".format(**TOOLCHAIN_INFO)],
#             "linux-aarch64": ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-{llvm_version}-minimal-linux-arm64.tar.zst".format(**TOOLCHAIN_INFO)],
#             "darwin-aarch64": ["{repository}/releases/download/{llvm_version}-{release_revision}/llvm-{llvm_version}-minimal-macos-arm64.tar.zst".format(**TOOLCHAIN_INFO)],
#         },
#         strip_prefix = {
#             "linux-x86_64": "llvm-{llvm_version}-minimal-linux-amd64".format(**TOOLCHAIN_INFO),
#             "linux-aarch64": "llvm-{llvm_version}-minimal-linux-arm64".format(**TOOLCHAIN_INFO),
#             "darwin-aarch64": "llvm-{llvm_version}-minimal-macos-arm64".format(**TOOLCHAIN_INFO),
#         },
#         sha256 = TOOLCHAIN_INTEGRITY.toolchain,
#     )
