load("@rules_oci//oci:pull.bzl", "oci_pull")

def load_sysroots():
    oci_pull(
        name = "minimal_sysroot_image",
        digest = "sha256:05d7f84044d02a2ec017efe9210a231d5b8ae630273b16a3293835853c269a56",
        image = "docker.io/joekralicky/sysroot",
        platforms = ["linux/amd64", "linux/arm64"],
    )
