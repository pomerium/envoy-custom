load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

envoy_cc_test(
    name = "pomerium_otel_test",
    srcs = [
        "pomerium_otel_test.cc",
    ],
    deps = [
        "//source/extensions/tracers/pomerium_otel",
        "@envoy//test/mocks/server:factory_context_mocks",
        "@envoy//test/mocks/server:tracer_factory_context_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/mocks/thread_local:thread_local_mocks",
        "@envoy//test/mocks/tracing:tracing_mocks",
        "@envoy//test/mocks/upstream:cluster_manager_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)
