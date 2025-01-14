load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

proto_library(
    name = "trace_context_proto",
    srcs = ["trace_context.proto"],
)

go_proto_library(
    name = "trace_context_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_proto"],
    importpath = "github.com/pomerium/envoy-custom/api/extensions/http/early_header_mutation/trace_context",
    proto = ":trace_context_proto",
    visibility = ["//visibility:public"],
)
