# load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")
LLVM_VERSION = "23.1.5"

LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "0",
}

TOOLCHAIN_INTEGRITY = {
    "cxx_cross_libs": {
        "linux-aarch64": "e40f092d4ac8879ed5ce57c06af0a7c51159f115ffbafd20db0dbce05fe8544c",
        "darwin-aarch64": "14e7d938a4b6c0404e9c6fe072e64993a1a14117c47a3208a3fe7e18b8bd6b4c",
    },
    "toolchain": {
        "linux-x86_64": "d0e2be3b10c5c19520a53a715123644337e6d3dc4395e2bde042ab69c6bbfc4f",
        "linux-aarch64": "54e5f7b264b3a8331c8d1ab42e4ad56a23874458ae2064420d8d7eb24cf36beb",
        "darwin-aarch64": "944f5e072ceb4f73e4422e125512dc267422d4dd57252d7dbd7020af4bc91ad0",
    },
    "extras": {
        "linux-x86_64": "96c81f9d166dfc01992d9c6a6bbad53ba87499567ebffa9b94f3ca88b7c52ba7",
        "linux-aarch64": "ab347f50a30382bc38ecf3cc87ac2c150def5d27b2cfc2e2e6146d08b49a798f",
    },
    "macos_utils": {
        "linux-x86_64": "cee147dbb473593f6d8aa6bc8cbb44563abb8e412c4b8c83b932e9aa7232ba40",
        "linux-aarch64": "3ef752730088c8f27ca06e7baf6de272c9d8486ed2d7889e4ded3bf35984b645",
        "darwin-aarch64": "db2f95386f2fdc8e1946f3f25ea19b4305aaf48d7eb7a03cc29f533ed7a997b4",
    },
    "sysroot": {
        "linux-x86_64": "7529bb9f55944ef908e9db923658bb73c41cb7383e9f3978aa27adddf3942ba7",
        "linux-aarch64": "bf40a8a7bc6e98121aa1ccca785238200bc54f7bba699850df7c78ecf083321a",
        "darwin-aarch64": "a8e8817c2f46c458fcb59fff86d31e947009b488560ee40fbb3b93b1580de4e4",
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
