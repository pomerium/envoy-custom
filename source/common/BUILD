load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "common_lib",
    srcs = [],
    hdrs = [
        "concepts.h",
        "factory.h",
        "fixed_string.h",
        "math.h",
        "optref.h",
        "span.h",
        "status.h",
        "type_traits.h",
        "types.h",
        "visit.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:statusor_lib",
    ],
)
