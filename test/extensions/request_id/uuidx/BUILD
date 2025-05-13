load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_test(
    name = "uuidx_test",
    srcs = ["uuidx_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/extensions/request_id/uuidx:pomerium_uuidx",
        "//source/extensions/request_id/uuidx:uuidx_cc_proto",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)
