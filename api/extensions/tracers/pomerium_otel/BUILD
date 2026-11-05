load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

package(default_visibility = ["//visibility:public"])

api_proto_package(
    has_services = True,
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/config/core/v3:pkg",
        "@xds//udpa/annotations:pkg",
    ],
)
