load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

def pomerium_envoy_toolchains():
    native.register_toolchains("@envoy//bazel/rbe/toolchains/configs/linux/gcc/config:cc-toolchain")
    arch_alias(
        name = "clang_platform",
        aliases = {
            "amd64": "@envoy//bazel/platforms/rbe:linux_x64",
            "aarch64": "@envoy//bazel/platforms/rbe:linux_arm64",
        },
    )
    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = "19.1.1",
        cxx_standard = {"": "c++23"},
        sysroot = {
            "linux-x86_64": "@minimal_sysroot_linux_amd64//:sysroot",
            "linux-aarch64": "@minimal_sysroot_linux_arm64//:sysroot",
        },
        toolchain_roots = {"": LLVM_PATH} if LLVM_PATH else {},
        extra_compiler_files = None if LLVM_PATH else "@llvm_toolchain_llvm//:lib/clang/19/share/msan_ignorelist.txt",
        cxx_builtin_include_directories = {
            "linux-x86_64": ["%workspace%/" + LLVM_PATH + "/lib/clang/19/share" if LLVM_PATH else "%workspace%/external/llvm_toolchain_llvm/lib/clang/19/share"],
            "linux-aarch64": ["%workspace%/" + LLVM_PATH + "/lib/clang/19/share" if LLVM_PATH else "%workspace%/external/llvm_toolchain_llvm/lib/clang/19/share"],
        },
    )
