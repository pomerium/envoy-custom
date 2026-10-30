load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
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

def _license_input_impl(ctx):
    dst = ctx.actions.declare_file("license_input.txt")
    if ctx.attr.license_from:
        license_name_value = ctx.attr.license_from[BuildSettingInfo].value
        ctx.actions.write(
            output = dst,
            content = license_name_value,
        )
    elif ctx.attr.license_str:
        ctx.actions.write(
            output = dst,
            content = ctx.attr.license_str,
        )
    else:
        fail("either license_from or license_str is required")

    return [DefaultInfo(
        files = depset(direct = [dst]),
    )]

_license_input = rule(
    implementation = _license_input_impl,
    attrs = {
        "license_from": attr.label(),
        "license_str": attr.string(),
    },
)

def image(
        name,
        srcs,
        repository = "ghcr.io/pomerium/envoy-custom",
        license = None,
        license_from = None,
        description = default_description,
        tag_exprs = default_tag_exprs,
        annotation_exprs = default_annotation_exprs):
    _tar_name = "_" + name + "_tar"
    _img_name = "_" + name + "_img"
    _repo_tags_name = "_" + name + "_repo_tags"
    _remote_tags_name = "_" + name + "_remote_tags"
    _img_labels_name = "_" + name + "_img_labels"
    _img_annotations_name = "_" + name + "_img_annotations"
    _license_input_name = "_" + name + "_license_input"
    pkg_tar(
        name = _tar_name,
        srcs = srcs,
        compressor = "@zstd//:zstd_cli",
        compressor_args = "-T0 -10",
        extension = "tar.zst",
        preserve_mtime = True,
    )

    _license_input(
        name = _license_input_name,
        license_str = license,
        license_from = license_from,
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
        data = [_license_input_name],
        out = "image_annotations_%s.txt" % name,
        args = ["-r", "--rawfile", "license_name", "$(location %s)" % _license_input_name],
        expand_args = True,
        filter = "[%s]" % ",".join([expr.format(
            description = description,
            license = r"\($license_name)",
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
