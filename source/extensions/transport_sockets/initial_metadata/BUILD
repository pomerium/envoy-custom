load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

envoy_cc_library(
    name = "filter_state_objects_lib",
    srcs = ["filter_state_objects.cc"],
    hdrs = ["filter_state_objects.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/registry",
        "@envoy//envoy/stream_info:filter_state_interface",
    ],
)

envoy_cc_library(
    name = "pomerium_initial_metadata",
    srcs = ["config.cc"],
    repository = "@envoy",
    deps = [
        ":filter_state_objects_lib",
        "//api/extensions/transport_sockets/initial_metadata:pkg_cc_proto",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:transport_socket_config_interface",
        "@envoy//source/common/config:utility_lib",
        "@envoy//source/extensions/transport_sockets/common:passthrough_lib",
    ],
)
