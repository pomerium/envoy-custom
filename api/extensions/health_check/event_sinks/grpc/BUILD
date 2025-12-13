load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

api_proto_package(
    has_services = True,
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg",
        "@envoy_api//envoy/data/core/v3:pkg",
    ],
)
