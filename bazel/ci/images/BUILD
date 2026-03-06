load("@aspect_bazel_lib//lib:jq.bzl", "jq")

jq(
    name = "repo_tags",
    srcs = ["//bazel/build_info:stable_status"],
    out = "repo_tags.txt",
    args = ["-r"],
    # \(.foo) is jq string interpolation
    filter = r'"pomerium/envoy-custom:\(.STABLE_BUILD_SCM_REVISION)"',
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
