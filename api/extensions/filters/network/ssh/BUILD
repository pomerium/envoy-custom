load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

proto_library(
    name = "ssh_proto",
    srcs = ["ssh.proto"],
    deps = [
        "@com_google_protobuf//:any_proto",
        "@com_google_protobuf//:timestamp_proto",
        "@com_google_protobuf//:wrappers_proto",
        "@envoy_api//envoy/config/core/v3:pkg",
    ],
)

go_proto_library(
    name = "ssh_go_proto",
    compilers = [
        "@io_bazel_rules_go//proto:go_proto",
        "@io_bazel_rules_go//proto:go_grpc_v2",
    ],
    importpath = "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh",
    proto = ":ssh_proto",
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg_go_proto",
    ],
)
