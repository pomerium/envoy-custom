load("@rules_oci//oci:defs.bzl", "oci_image", "oci_load")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

def image(name, srcs):
    _tar_name = "_" + name + "_tar"
    pkg_tar(
        name = _tar_name,
        srcs = srcs,
        compressor = "@zstd//:zstd_cli",
        compressor_args = "-T0 -10",
        extension = "tar.zst",
    )

    oci_image(
        name = name,
        architecture = select({
            "@platforms//cpu:x86_64": "x86_64",
            "@platforms//cpu:aarch64": "aarch64",
        }),
        os = select({
            "@platforms//os:linux": "linux",
            "@platforms//os:macos": "darwin",
        }),
        labels = "//bazel/ci/images:image_labels",
        tars = [_tar_name],
        visibility = ["//visibility:public"],
        entrypoint = ["/envoy"],
    )

    oci_load(
        name = "docker_load." + name,
        image = name,
        repo_tags = "//bazel/ci/images:repo_tags",
        visibility = ["//visibility:public"],
    )
