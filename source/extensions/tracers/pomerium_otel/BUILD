load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
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
