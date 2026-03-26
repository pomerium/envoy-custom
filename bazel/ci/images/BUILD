load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load(":oci.bzl", "REPO_NAME")

# List of jq expressions to generate image tags
tag_exprs = [
    # full commit hash
    ".STABLE_BUILD_SCM_REVISION",
    # go module pseudo version format
    "((.STABLE_BUILD_SCM_REVISION_TIMESTAMP | tostring) + \"-\" + (.STABLE_BUILD_SCM_REVISION | tostring | .[0:12]))",
    "(.STABLE_BUILD_SCM_TAG // \"\" | split(\" \"))",
]

jq(
    name = "repo_tags",
    srcs = ["//bazel/build_info:stable_status"],
    out = "repo_tags.txt",
    args = [
        "-r",
        "--arg",
        "repo",
        REPO_NAME,
    ],
    filter = "[%s]" % ",".join(tag_exprs) + r' | flatten | map(select(.)) | map("\($repo):\(.)") | .[]',
    visibility = ["//visibility:public"],
)

jq(
    name = "remote_tags",
    srcs = ["//bazel/build_info:stable_status"],
    out = "remote_tags.txt",
    args = [
        "-r",
    ],
    filter = "[%s]" % ",".join(tag_exprs) + r"| .[]",
    visibility = ["//visibility:public"],
)

jq(
    name = "image_labels",
    srcs = ["//bazel/build_info:combined_status"],
    out = "image_labels.txt",
    args = ["-r"],
    # convert the json object fields to plain key=value entries
    filter = r'to_entries | map("\(.key)=\(.value | tostring)") | .[]',
    visibility = ["//visibility:public"],
)

genrule(
    name = "crane_bin",
    outs = ["crane"],
    cmd = "cp $(CRANE_BIN) $@",
    executable = True,
    toolchains = ["@oci_crane_toolchains//:current_toolchain"],
)

exports_files(["update_index.sh.tpl"])
