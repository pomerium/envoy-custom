load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

envoy_cc_library(
    name = "pomerium_trace_context",
    srcs = [
        "config.cc",
        "trace_context.cc",
    ],
    hdrs = [
        "config.h",
        "trace_context.h",
    ],
    deps = [
        "//api/extensions/http/early_header_mutation/trace_context:pkg_cc_proto",
        "@envoy//envoy/http:early_header_mutation_interface",
        "@envoy//envoy/registry",
        "@envoy//source/common/common:base64_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/http:header_mutation_lib",
    ],
)
