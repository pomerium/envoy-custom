load("@rules_oci//oci:pull.bzl", "oci_pull")

def load_cxx_libs():
    oci_pull(
        name = "cxx_libs_image",
        digest = "sha256:e73feb1d063e909b4683da80a26ec21cbf2eec53deabf14ca322f4bd94c44dca",
        image = "docker.io/joekralicky/cxx-libs:llvm-22.1.1",
        platforms = ["linux/amd64", "linux/arm64"],
    )

def load_darwin_cxx_libs():
    oci_pull(
        name = "cxx_libs_image_darwin",
        digest = "sha256:b288f410f9dead3145f1eeb73fceaa9fbdd00527a83dc97c01993b2b0d865136",
        image = "docker.io/joekralicky/cxx-libs-darwin:llvm-22.1.1",
        platforms = ["linux/amd64", "linux/arm64"],
    )
