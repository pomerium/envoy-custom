load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "pomerium_otel",
    srcs = [
        "config.cc",
        "span.cc",
        "tracer_impl.cc",
    ],
    hdrs = [
        "config.h",
        "span.h",
        "tracer_impl.h",
        "typeutils.h",
    ],
    repository = "@envoy",
    deps = [
        ":pomerium_otel_cc_proto",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/extensions/tracers/opentelemetry:opentelemetry_tracer_lib",
    ],
)

cc_proto_library(
    name = "pomerium_otel_cc_proto",
    deps = ["//api/extensions/tracers/pomerium_otel:pomerium_otel_proto"],
)

envoy_cc_test(
    name = "pomerium_otel_test",
    srcs = [
        "pomerium_otel_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":pomerium_otel",
        ":pomerium_otel_cc_proto",
        "@envoy//test/mocks/server:tracer_factory_context_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/mocks/thread_local:thread_local_mocks",
        "@envoy//test/mocks/tracing:tracing_mocks",
        "@envoy//test/mocks/upstream:cluster_manager_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)
