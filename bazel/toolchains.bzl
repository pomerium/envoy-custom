load("@envoy_repo//:compiler.bzl", "LLVM_PATH")
load("@envoy_toolshed//repository:utils.bzl", "arch_alias")
load("@toolchains_llvm//toolchain:rules.bzl", "llvm_toolchain")

LLVM_VERSION = "22.1.1"
LLVM_MAJOR_VERSION = LLVM_VERSION.split(".")[0]

TOOLCHAIN_INFO = {
    "llvm_version": LLVM_VERSION,
    "llvm_major_version": LLVM_MAJOR_VERSION,
    "repository": "https://github.com/pomerium/toolchain-utils",
    "release_revision": "3",
}

TOOLCHAIN_INTEGRITY = struct(
    toolchain = {
        "linux-x86_64": "1ce2cc8eeddf18168426c95f490ea1c28432324d310d3f4ed9c0047fec2c27ed",
        "linux-aarch64": "d2240f6c9fb0b95c9034995239c0a246ba057c569012859f0febb08e819f950f",
        "darwin-aarch64": "d027d7abfd2accc0303e5d54d930efbd73127dff62d8dedd08ce4f7e528805a9",
    },
    sysroot = {
        "linux-x86_64": "c10fe789f62979ae75ab052702202bec94778d6b2c3d0d2457460d6fdc27eba7",
        "linux-aarch64": "387e15773486407c5bf048227bbcce749f880de4046646095b8b7868c1b303a1",
        "darwin-aarch64": "afe40e4fc8393535524bd35d0a4d4901a000441ca722cc4d3e7267aaba50861e",
    },
    cxx_cross_libs = {
        "linux-aarch64": "120c0261863967ba8a11dd687fa4fb7fc081a1b600cc2b712224e597729e55df",
        "darwin-aarch64": "258c14feacb133ba3693249d6b505d7bd7c28edc74c006b7e2a899b3b3ff8706",
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
