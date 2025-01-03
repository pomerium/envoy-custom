load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

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
    repository = "@envoy",
    deps = [
        ":trace_context_cc_proto",
        "@envoy//envoy/http:early_header_mutation_interface",
        "@envoy//envoy/registry",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/http:header_mutation_lib",
    ],
)

cc_proto_library(
    name = "trace_context_cc_proto",
    deps = ["trace_context_proto"],
)

proto_library(
    name = "trace_context_proto",
    srcs = ["trace_context.proto"],
)

envoy_cc_test(
    name = "trace_context_test",
    srcs = ["trace_context_test.cc"],
    repository = "@envoy",
    deps = [
        ":pomerium_trace_context",
        ":trace_context_cc_proto",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)
