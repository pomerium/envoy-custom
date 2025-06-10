load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test_library(
    name = "test_common_lib",
    srcs = [],
    hdrs = [
        "test_common.h",
    ],
    repository = "@envoy",
    deps = [
        "//source/common:common_lib",
        "@com_google_absl//absl/random",
        "@envoy//test/test_common:logging_lib",
    ],
)
