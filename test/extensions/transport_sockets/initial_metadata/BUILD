load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

envoy_cc_test(
    name = "initial_metadata_test",
    srcs = ["initial_metadata_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/extensions/transport_sockets/initial_metadata:pomerium_initial_metadata",
        "//test/test_common:test_common_lib",
        "@envoy//source/extensions/filters/network/set_filter_state:config",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "@envoy//test/integration:common_extensions_lib",
        "@envoy//test/integration:http_integration_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)
