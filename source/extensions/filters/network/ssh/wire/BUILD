load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "wire_lib",
    srcs = [
        "buffer_io.cc",
        "messages.cc",
    ],
    hdrs = [
        "buffer_io.h",
        "common.h",
        "encoding.h",
        "field.h",
        "key_field.h",
        "message_types.h",
        "messages.h",
        "packet.h",
        "util.h",
    ] + [
        "internal/field_impl.h",
        "internal/message_groups.h",
        "internal/message_impl.h",
        "internal/message_traits.h",
        "internal/top_level_visitor.h",
        "internal/validation.h",
    ],
    copts = [
        "-Wimplicit-fallthrough",
        "-Wimplicit-int-conversion",
        "-Wunsafe-buffer-usage",
    ],
    repository = "@envoy",
    deps = [
        ":wire_lib_common",
        "//source/common:common_lib",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//source/common/common:utility_lib",
        "@magic_enum",
    ],
)

envoy_cc_library(
    name = "wire_lib_common",
    srcs = [],
    hdrs = ["common.h"],
    copts = [
        "-Wimplicit-fallthrough",
        "-Wimplicit-int-conversion",
        "-Wunsafe-buffer-usage",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:fmt_lib",
    ],
)
