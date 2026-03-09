load("@rules_oci//oci:defs.bzl", "oci_image", "oci_image_index", "oci_load", "oci_push")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

REPO_NAME = "pomerium/envoy-custom"

def image(name, srcs):
    _tar_name = "_" + name + "_tar"
    _img_name = "_" + name + "_img"
    pkg_tar(
        name = _tar_name,
        srcs = srcs,
        compressor = "@zstd//:zstd_cli",
        compressor_args = "-T0 -10",
        extension = "tar.zst",
        preserve_mtime = True,
    )

    oci_image(
        name = _img_name,
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
        entrypoint = ["/envoy"],
    )

    oci_image_index(
        name = name,
        images = [
            _img_name,
        ],
        visibility = ["//visibility:public"],
    )

    oci_push(
        name = "push." + name,
        image = name,
        repository = REPO_NAME,
        remote_tags = "//bazel/ci/images:remote_tags",
        visibility = ["//visibility:public"],
    )

    oci_load(
        name = "docker_load." + name,
        image = name,
        repo_tags = "//bazel/ci/images:repo_tags",
        visibility = ["//visibility:public"],
    )
