load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

proto_library(
    name = "session_recording_proto",
    srcs = ["session_recording.proto"],
    deps = [
        "@com_google_protobuf//:any_proto",
        "@com_google_protobuf//:timestamp_proto",
        "@envoy_api//envoy/config/core/v3:pkg",
    ],
)

go_proto_library(
    name = "session_recording_go_proto",
    compilers = [
        "@io_bazel_rules_go//proto:go_proto",
    ],
    importpath = "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh/filters/session_recording",
    proto = ":session_recording_proto",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg_go_proto",
    ],
)
