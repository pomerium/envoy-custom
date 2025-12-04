load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "grpc_event_sink",
    srcs = [
        "event_sink.cc",
    ],
    hdrs = [
        "event_sink.h",
    ],
    repository = "@envoy",
    deps = [
        "//api/extensions/health_check/event_sinks/grpc:pkg_cc_proto",
        "@envoy//envoy/registry",
        "@envoy//envoy/upstream:health_check_event_sink_interface",
        "@envoy//source/common/grpc:typed_async_client_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/data/core/v3:pkg_cc_proto",
    ],
)
