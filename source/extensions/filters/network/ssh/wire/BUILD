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
    copts = [
        "-Wimplicit-fallthrough",
        "-Wimplicit-int-conversion",
        "-Wunsafe-buffer-usage",
        "--system-header-prefix=envoy/",
        "--system-header-prefix=absl/",
        "--system-header-prefix=api/",
        "--system-header-prefix=source/common/common/",
        "--system-header-prefix=source/common/buffer/",
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
