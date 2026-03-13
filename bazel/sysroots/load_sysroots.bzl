load("@rules_oci//oci:pull.bzl", "oci_pull")

def load_sysroots():
    oci_pull(
        name = "minimal_sysroot_image",
        digest = "sha256:a9a7c6a2639a82dc6298a0f724618c8eb68cad17a53dc0afaa2559fad03a22ca",
        image = "docker.io/joekralicky/sysroot",
        platforms = ["linux/amd64", "linux/arm64"],
    )
