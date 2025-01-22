load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

proto_library(
    name = "ssh_proto",
    srcs = ["ssh.proto"],
)

go_proto_library(
    name = "ssh_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_proto"],
    importpath = "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh",
    proto = ":ssh_proto",
    visibility = ["//visibility:public"],
)
