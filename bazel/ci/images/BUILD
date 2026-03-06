load("@aspect_bazel_lib//lib:jq.bzl", "jq")

repo_name = "pomerium/envoy-custom"

# List of jq expressions to generate image tags
tag_exprs = [
    # full commit hash
    ".STABLE_BUILD_SCM_REVISION",
    # go module pseudo version format
    "((.STABLE_BUILD_SCM_REVISION_TIMESTAMP | tostring) + \"-\" + (.STABLE_BUILD_SCM_REVISION | tostring | .[0:12]))",
]

jq(
    name = "repo_tags",
    srcs = ["//bazel/build_info:stable_status"],
    out = "repo_tags.txt",
    args = [
        "-r",
        "--arg",
        "repo",
        repo_name,
    ],
    filter = "[%s]" % ",".join(tag_exprs) + r'| map("\($repo):\(.)") | .[]',
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
