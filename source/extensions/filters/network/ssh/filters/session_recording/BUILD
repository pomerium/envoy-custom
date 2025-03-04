load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "session_recording_filter",
    srcs = [
        "config.cc",
    ],
    hdrs = [
        "config.h",
    ],
    repository = "@envoy",
    deps = [
        ":session_recording_cc_proto",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "@envoy//source/extensions/filters/network/generic_proxy/interface:filter_interface",
    ],
)

cc_proto_library(
    name = "session_recording_cc_proto",
    deps = ["//api/extensions/filters/network/ssh/filters/session_recording:session_recording_proto"],
)
