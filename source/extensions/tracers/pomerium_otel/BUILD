load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

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
    deps = [
        "//api/extensions/tracers/pomerium_otel:pkg_cc_proto",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/extensions/tracers/opentelemetry:opentelemetry_tracer_lib",
    ],
)
