load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

def pomerium_envoy_toolchains():
    arch_alias(
        name = "clang_platform",
        aliases = {
            "amd64": "@envoy//bazel/platforms/rbe:linux_x64",
            "aarch64": "@envoy//bazel/platforms/rbe:linux_arm64",
        },
    )
    llvm_toolchain(
        name = "llvm_toolchain",
        llvm_version = "22.1.1",
        cxx_standard = {"": "c++23"},
        sysroot = {
            "linux-x86_64": "@minimal_sysroot_linux_amd64//:sysroot",
            "linux-aarch64": "@minimal_sysroot_linux_arm64//:sysroot",
            "darwin-aarch64": "@macos_sysroot//:sysroot",
        },
        cxx_cross_lib = {
            "linux-x86_64": "@cxx_libs_linux_amd64//:cxx_libs",
            "linux-aarch64": "@cxx_libs_linux_arm64//:cxx_libs",
            "darwin-aarch64": "@cxx_libs_darwin_arm64//:cxx_libs",
        },
        libclang_rt = {
            "@cxx_libs_linux_amd64//lib:libclang_rt.builtins.a": "x86_64-unknown-linux-gnu/libclang_rt.builtins.a",
            "@cxx_libs_linux_amd64//lib:clang_rt.crtbegin.o": "x86_64-unknown-linux-gnu/clang_rt.crtbegin.o",
            "@cxx_libs_linux_amd64//lib:clang_rt.crtend.o": "x86_64-unknown-linux-gnu/clang_rt.crtend.o",
            "@cxx_libs_linux_arm64//lib:libclang_rt.builtins.a": "aarch64-unknown-linux-gnu/libclang_rt.builtins.a",
            "@cxx_libs_linux_arm64//lib:clang_rt.crtbegin.o": "aarch64-unknown-linux-gnu/clang_rt.crtbegin.o",
            "@cxx_libs_linux_arm64//lib:clang_rt.crtend.o": "aarch64-unknown-linux-gnu/clang_rt.crtend.o",
            "@cxx_libs_darwin_arm64//lib:libclang_rt.osx.a": "aarch64-apple-macosx/libclang_rt.osx.a",
        },
        extra_link_flags = {
            "linux-x86_64": ["-rtlib=compiler-rt", "-l:libunwind.a"],
            "linux-aarch64": ["-rtlib=compiler-rt", "-l:libunwind.a"],
            "darwin-aarch64": ["-rtlib=compiler-rt"],
        },
        toolchain_roots = {"": LLVM_PATH} if LLVM_PATH else {},
        extra_compiler_files = None if LLVM_PATH else "@llvm_toolchain_llvm//:lib/clang/22/share/msan_ignorelist.txt",
        cxx_builtin_include_directories = {
            "linux-x86_64": ["%workspace%/" + LLVM_PATH + "/lib/clang/22/share" if LLVM_PATH else "%workspace%/external/llvm_toolchain_llvm/lib/clang/22/share"],
            "linux-aarch64": ["%workspace%/" + LLVM_PATH + "/lib/clang/22/share" if LLVM_PATH else "%workspace%/external/llvm_toolchain_llvm/lib/clang/22/share"],
            "darwin-aarch64": ["%workspace%/" + LLVM_PATH + "/lib/clang/22/share" if LLVM_PATH else "%workspace%/external/llvm_toolchain_llvm/lib/clang/22/share"],
        },
        extra_llvm_distributions = {
            "LLVM-22.1.1-Linux-X64.tar.xz": "sha256:efc4d945744f951df00ec72c5b31da5d5a2eaf1d53cc7c9d0644f93f0f9e817d",
            "LLVM-22.1.1-Linux-ARM64.tar.xz": "sha256:a807a16a4dd9a288b6ad3d507df4eae47dfdfbccab118170ebd216b85370a065",
            "LLVM-22.1.1-macOS-ARM64.tar.xz": "sha256:3839802601439300fc8d1d378bc26732e879e1ca80a220f7d6764ed229053e92",
        },
    )
