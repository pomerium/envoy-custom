load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

def pomerium_envoy_toolchains():
    arch_alias(
        name = "clang_platform",
        aliases = {
            # Note: explicit repo name required here
            "amd64": "@pomerium_envoy//bazel/platforms/rbe:linux_x64",
            "aarch64": "@pomerium_envoy//bazel/platforms/rbe:linux_arm64",
        },
    )
    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = "19.1.1",
        # llvm_version = "21.1.6",
        cxx_standard = {"": "c++23"},
        sysroot = None if LLVM_PATH else {
            "linux-x86_64": "@sysroot_linux_amd64//:sysroot",
            "linux-aarch64": "@sysroot_linux_arm64//:sysroot",
        },
        toolchain_roots = {"": LLVM_PATH} if LLVM_PATH else {},
        extra_compiler_files = None if LLVM_PATH else "@llvm_toolchain_llvm//:lib/clang/19/share/msan_ignorelist.txt",
        cxx_builtin_include_directories = {"": "%s/lib/clang/19/share" % LLVM_PATH} if LLVM_PATH else None,
    )
