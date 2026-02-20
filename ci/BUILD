package(default_visibility = ["//visibility:public"])

filegroup(
    name = "llvm_toolchain_targets",
    srcs = [
        "@llvm_toolchain_llvm//:cxx_builtin_include",
        "@llvm_toolchain_llvm//:extra_config_site",
        "@llvm_toolchain_llvm//:include",
        "@llvm_toolchain_llvm//:ld",
        "@llvm_toolchain_llvm//:lib/clang/19/share/msan_ignorelist.txt",
        "@llvm_toolchain_llvm//:lib_legacy",
        "@llvm_toolchain_llvm//:libclang",
    ] + [
        "@llvm_toolchain_llvm//:bin/clang",
        "@llvm_toolchain_llvm//:bin/clang-19",
        "@llvm_toolchain_llvm//:bin/clang-apply-replacements",
        "@llvm_toolchain_llvm//:bin/clang-format",
        "@llvm_toolchain_llvm//:bin/clang-tidy",
        "@llvm_toolchain_llvm//:bin/lld",
        "@llvm_toolchain_llvm//:bin/llvm-ar",
        "@llvm_toolchain_llvm//:bin/llvm-as",
        "@llvm_toolchain_llvm//:bin/llvm-cov",
        "@llvm_toolchain_llvm//:bin/llvm-dwp",
        "@llvm_toolchain_llvm//:bin/llvm-nm",
        "@llvm_toolchain_llvm//:bin/llvm-objcopy",
        "@llvm_toolchain_llvm//:bin/llvm-objdump",
        "@llvm_toolchain_llvm//:bin/llvm-profdata",
        "@llvm_toolchain_llvm//:bin/llvm-ranlib",
        "@llvm_toolchain_llvm//:bin/llvm-readelf",
        "@llvm_toolchain_llvm//:bin/llvm-readobj",
        "@llvm_toolchain_llvm//:bin/llvm-strip",
        "@llvm_toolchain_llvm//:bin/llvm-symbolizer",
    ],
)
