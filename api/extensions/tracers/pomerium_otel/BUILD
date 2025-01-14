load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

proto_library(
    name = "pomerium_otel_proto",
    srcs = ["pomerium_otel.proto"],
    deps = [
        "@com_envoyproxy_protoc_gen_validate//validate:validate_proto",
        "@com_github_cncf_xds//udpa/annotations:pkg",
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/config/core/v3:pkg",
    ],
)

go_proto_library(
    name = "pomerium_otel_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_proto"],
    importpath = "github.com/pomerium/envoy-custom/api/extensions/tracers/pomerium_otel",
    proto = ":pomerium_otel_proto",
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_cncf_xds//udpa/annotations:pkg_go_proto",
        "@envoy_api//envoy/config/core/v3:pkg_go_proto",
    ],
)
