load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "wire_lib",
    hdrs = [
        "common.h",
        "encoding.h",
        "field.h",
        "messages.h",
        "util.h",
    ],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:utility_lib",
    ],
)

envoy_cc_test(
    name = "wire_lib_test",
    srcs = ["messages_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_lib",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)
