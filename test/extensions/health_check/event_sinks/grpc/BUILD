load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

licenses(["notice"])  # Apache 2

envoy_cc_test(
    name = "grpc_event_sink_test",
    srcs = ["event_sink_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/extensions/health_check/event_sinks/grpc:grpc_event_sink",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/server:health_checker_factory_context_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)
