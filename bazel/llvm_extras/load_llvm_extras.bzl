load("//bazel/llvm_extras:llvm_extras.bzl", "llvm_extras")

def load_llvm_extras():
    llvm_extras(
        name = "llvm_extras_linux_amd64",
        os = "linux",
        arch = "amd64",
    )
    llvm_extras(
        name = "llvm_extras_linux_arm64",
        os = "linux",
        arch = "arm64",
    )
