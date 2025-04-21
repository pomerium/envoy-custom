load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "wire_lib",
    srcs = [
        "encoding.cc",
        "messages.cc",
    ],
    hdrs = [
        "common.h",
        "encoding.h",
        "field.h",
        "message_traits.h",
        "messages.h",
        "packet.h",
        "util.h",
        "validation.h",
    ],
    repository = "@envoy",
    deps = [
        ":wire_lib_common",
        "//source/common:common_lib",
        "//source/extensions/filters/network/ssh:ssh_common_lib",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//source/common/common:utility_lib",
    ],
)

envoy_cc_library(
    name = "wire_lib_common",
    srcs = [],
    hdrs = ["common.h"],
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:fmt_lib",
    ],
)
