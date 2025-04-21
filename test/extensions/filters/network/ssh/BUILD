load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_cc_test_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test_library(
    name = "test_common",
    srcs = [],
    hdrs = [
        "test_common.h",
    ],
    repository = "@envoy",
)

envoy_cc_test(
    name = "client_transport_test",
    srcs = [
        "client_transport_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_common",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)
