load("@rules_oci//oci:pull.bzl", "oci_pull")

def load_cxx_libs():
    oci_pull(
        name = "cxx_libs_image",
        digest = "sha256:430015b97f9a53d3a5513f543c6a4cbf8253f3dcb6ffa7a091749f317e378108",
        image = "docker.io/joekralicky/cxx-libs:llvm-22.1.1",
        platforms = ["linux/amd64", "linux/arm64"],
    )
