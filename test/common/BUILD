load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

envoy_cc_test(
    name = "status_test",
    srcs = ["status_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/common:common_lib",
    ],
)
