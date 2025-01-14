load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

proto_library(
    name = "uuidx_proto",
    srcs = ["uuidx.proto"],
    deps = [
        "@com_google_protobuf//:wrappers_proto",
    ],
)

go_proto_library(
    name = "uuidx_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_proto"],
    importpath = "github.com/pomerium/envoy-custom/api/extensions/request_id/uuidx",
    proto = ":uuidx_proto",
    visibility = ["//visibility:public"],
)
