load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "ssh_common_lib",
    srcs = [],
    hdrs = ["common.h"],
    repository = "@envoy",
    deps = [
        "//source/common:common_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:statusor_lib",
    ],
)

cc_proto_library(
    name = "ssh_cc_proto",
    deps = ["//api/extensions/filters/network/ssh:ssh_proto"],
)
