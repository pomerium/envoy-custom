load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_cc_test_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "wire_lib",
    srcs = [
        "messages.cc",
    ],
    hdrs = [
        "common.h",
        "encoding.h",
        "field.h",
        "message_traits.h",
        "messages.h",
        "packet.h",
        "util.h",
    ],
    repository = "@envoy",
    deps = [
        ":wire_lib_common",
        "//source/extensions/filters/network/ssh:ssh_common_lib",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//source/common/common:utility_lib",
    ],
)

envoy_cc_library(
    name = "wire_lib_common",
    hdrs = ["common.h"],
    repository = "@envoy",
    deps = [
        "@envoy//source/common/common:fmt_lib",
    ],
)

envoy_cc_test(
    name = "encoding_test",
    srcs = ["encoding_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_lib",
        ":wire_test_util",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test(
    name = "messages_test",
    srcs = ["messages_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_lib",
        ":wire_test_util",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test(
    name = "packet_test",
    srcs = ["packet_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_lib",
        ":wire_test_util",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test(
    name = "field_test",
    srcs = ["field_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_lib",
        ":wire_test_util",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test_library(
    name = "wire_test_common",
    hdrs = [
        "wire_test_common.h",
    ],
    repository = "@envoy",
)

envoy_cc_test_library(
    name = "wire_test_util",
    hdrs = [
        "wire_test_util.h",
    ],
    repository = "@envoy",
    deps = [
        ":wire_lib_common",
        ":wire_test_common",
    ],
)
