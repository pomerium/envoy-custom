load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_test(
    name = "trace_context_test",
    srcs = [
        "config_test.cc",
        "trace_context_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/http/early_header_mutation/trace_context:pomerium_trace_context",
        "//source/extensions/http/early_header_mutation/trace_context:trace_context_cc_proto",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)
