load("@aspect_bazel_lib//lib:yq.bzl", "yq")
load("@envoy//bazel:envoy_build_system.bzl", "envoy_package")

envoy_package()

yq(
    name = "coverage_config",
    srcs = [":coverage.yaml"],
    outs = ["coverage_config.json"],
    args = ["-o=json"],
    visibility = ["//visibility:public"],
)
