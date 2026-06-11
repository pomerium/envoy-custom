load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load("@rules_oci//oci:defs.bzl", "oci_image", "oci_load")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")
load("//bazel/ci/images:update_index.bzl", "oci_update_index")

# List of jq expressions to generate image tags
default_tag_exprs = [
    # full commit hash
    ".STABLE_BUILD_SCM_REVISION",
    # go module pseudo version format
    "((.STABLE_BUILD_SCM_REVISION_TIMESTAMP | tostring) + \"-\" + (.STABLE_BUILD_SCM_REVISION | tostring | .[0:12]))",
    "(.STABLE_BUILD_SCM_TAG // \"\" | split(\" \"))",
]

default_description = "This is an intermediate CI artifact used in the Pomerium build process. It is not intended to be run directly. " + \
                      "If you are looking for the Pomerium docker image, it can be found at https://hub.docker.com/r/pomerium/pomerium."

default_annotation_exprs = [
    r'"org.opencontainers.image.source=" + (.BUILD_SCM_REMOTE | rtrimstr(".git") | tostring)',
    r'"org.opencontainers.image.description={description}"',
    r'"org.opencontainers.image.licenses={license}"',
]

def image(
        name,
        srcs,
        repository = "ghcr.io/pomerium/envoy-custom",
        license = "Apache-2.0",
        description = default_description,
        tag_exprs = default_tag_exprs,
        annotation_exprs = default_annotation_exprs):
    _tar_name = "_" + name + "_tar"
    _img_name = "_" + name + "_img"
    _repo_tags_name = "_" + name + "_repo_tags"
    _remote_tags_name = "_" + name + "_remote_tags"
    _img_labels_name = "_" + name + "_img_labels"
    _img_annotations_name = "_" + name + "_img_annotations"
    pkg_tar(
        name = _tar_name,
        srcs = srcs,
        compressor = "@zstd//:zstd_cli",
        compressor_args = "-T0 -10",
        extension = "tar.zst",
        preserve_mtime = True,
    )

    jq(
        name = _repo_tags_name,
        srcs = ["@pomerium_envoy//bazel/build_info:stable_status"],
        out = "repo_tags_%s.txt" % name,
        args = [
            "-r",
            "--arg",
            "repo",
            repository,
        ],
        filter = "[%s]" % ",".join(tag_exprs) + r' | flatten | map(select(.)) | map("\($repo):\(.)") | .[]',
    )

    jq(
        name = _remote_tags_name,
        srcs = ["@pomerium_envoy//bazel/build_info:stable_status"],
        out = "remote_tags_%s.txt" % name,
        args = ["-r"],
        filter = "[%s]" % ",".join(tag_exprs) + r" | flatten | map(select(.)) | .[]",
    )

    jq(
        name = _img_labels_name,
        srcs = ["@pomerium_envoy//bazel/build_info:combined_status"],
        out = "image_labels_%s.txt" % name,
        args = ["-r"],
        # convert the json object fields to plain key=value entries
        filter = r'to_entries | map("\(.key)=\(.value | tostring)") | .[]',
    )

    jq(
        name = _img_annotations_name,
        srcs = ["@pomerium_envoy//bazel/build_info:combined_status"],
        out = "image_annotations_%s.txt" % name,
        args = ["-r"],
        filter = "[%s]" % ",".join([expr.format(
            description = description,
            license = license,
        ) for expr in annotation_exprs]) + r"| .[]",
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
        labels = _img_labels_name,
        annotations = _img_annotations_name,
        tars = [_tar_name],
        entrypoint = ["/envoy"],
    )

    oci_update_index(
        name = "update_index." + name,
        repository = repository,
        image = _img_name,
        manifest_digest = _img_name + ".digest",
        index_tags = _remote_tags_name,
        visibility = ["//visibility:public"],
    )

    oci_load(
        name = "docker_load." + name,
        image = _img_name,
        repo_tags = _repo_tags_name,
        visibility = ["//visibility:public"],
    )
