load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test_library",
)
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "channel_filter_conformance_test_config_lib",
    srcs = [],
    hdrs = ["channel_filter_conformance_test_config.h"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/common/protobuf",
    ],
)

envoy_cc_test_library(
    name = "channel_filter_conformance_test",
    srcs = [
        "channel_filter_conformance_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":channel_filter_conformance_test_config_lib",
        "//api/extensions/bootstrap/dynamic_extension_loader:pkg_cc_proto",
        "//source/extensions/bootstrap/dynamic_extension_loader",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh:integration_lib",
        "@envoy//source/extensions/filters/http/router:config",
        "@envoy//source/extensions/filters/network/http_connection_manager:config",
        "@envoy//test/integration:integration_lib",
        "@envoy//test/test_common:status_utility_lib",
        "@envoy_api//envoy/extensions/filters/http/router/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)
