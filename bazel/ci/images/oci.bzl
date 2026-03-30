load("@aspect_bazel_lib//lib:expand_template.bzl", "expand_template")
load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load("@aspect_bazel_lib//lib:paths.bzl", "BASH_RLOCATION_FUNCTION", "to_rlocation_path")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_image_index", "oci_load", "oci_push")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load("//bazel/ci/images:update_index.bzl", "oci_update_index")

def image(name, srcs, repository = "ghcr.io/pomerium/envoy-custom"):
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
        annotations = "//bazel/ci/images:image_annotations",
        tars = [_tar_name],
        entrypoint = ["/envoy"],
    )

    oci_update_index(
        name = "update_index." + name,
        repository = repository,
        image = _img_name,
        manifest_digest = _img_name + ".digest",
        index_tags = "//bazel/ci/images:remote_tags",
        visibility = ["//visibility:public"],
    )

    oci_load(
        name = "docker_load." + name,
        image = _img_name,
        repo_tags = "//bazel/ci/images:repo_tags",
        visibility = ["//visibility:public"],
    )
