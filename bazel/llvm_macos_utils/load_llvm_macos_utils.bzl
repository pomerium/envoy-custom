load("//bazel/llvm_macos_utils:llvm_macos_utils.bzl", "llvm_macos_utils")

def load_llvm_macos_utils():
    llvm_macos_utils(
        name = "llvm_macos_utils_linux_amd64",
        os = "linux",
        arch = "amd64",
    )
    llvm_macos_utils(
        name = "llvm_macos_utils_linux_arm64",
        os = "linux",
        arch = "arm64",
    )
    llvm_macos_utils(
        name = "llvm_macos_utils_darwin_arm64",
        os = "macos",
        arch = "arm64",
    )
