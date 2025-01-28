load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "pomerium_ssh",
    srcs = [
        "config.cc",
        "kex.cc",
        "server_transport.cc",
        "ssh-sk-null.cc",
        "util.cc",
    ],
    hdrs = [
        "config.h",
        "kex.h",
        "keys.h",
        "messages.h",
        "server_transport.h",
        "util.h",
    ],
    repository = "@envoy",
    deps = [
        ":ssh_cc_proto",
        "//:openssh",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:base64_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/common/crypto:utility_lib",
        "@envoy//source/extensions/filters/network:well_known_names",
        "@envoy//source/extensions/filters/network/common:factory_base_lib",
        "@envoy//source/extensions/filters/network/generic_proxy/interface:codec_interface",
    ],
)

cc_proto_library(
    name = "ssh_cc_proto",
    deps = ["//api/extensions/filters/network/ssh:ssh_proto"],
)

envoy_cc_test(
    name = "ssh_test",
    srcs = ["messages_test.cc"],
    repository = "@envoy",
    deps = [
        ":pomerium_ssh",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)
