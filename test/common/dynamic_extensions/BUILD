load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

envoy_cc_test(
    name = "dynamic_extensions_test",
    srcs = [
        "dynamic_extensions_test.cc",
    ],
    data = [
        "//test/common/dynamic_extensions/test:test_http_factory",
        "//test/common/dynamic_extensions/test:test_invalid_id",
        "//test/common/dynamic_extensions/test:test_md_unknown_keys",
        "//test/common/dynamic_extensions/test:test_missing_symbol",
        "//test/common/dynamic_extensions/test:test_no_config",
        "//test/common/dynamic_extensions/test:test_no_config_2",
        "//test/common/dynamic_extensions/test:test_no_id",
        "//test/common/dynamic_extensions/test:test_no_init",
        "//test/common/dynamic_extensions/test:test_no_metadata",
        "//test/common/dynamic_extensions/test:test_optional_config",
        "//test/common/dynamic_extensions/test:test_required_config",
        "//test/common/dynamic_extensions/test:test_tls",
        "//test/common/dynamic_extensions/test:test_version_mismatch",
        "//tools:read-extension",
    ],
    linkopts = [
        "-Wl,-E",
    ],
    repository = "@envoy",
    shard_count = 8,
    deps = [
        "//api/extensions/bootstrap/dynamic_extension_loader:pkg_cc_proto",
        "//source/extensions/bootstrap/dynamic_extension_loader",
        "@envoy//source/extensions/filters/http/router:config",
        "@envoy//source/extensions/filters/network/http_connection_manager:config",
        "@envoy//test/integration:integration_lib",
        "@envoy//test/test_common:status_utility_lib",
        "@envoy_api//envoy/extensions/filters/http/router/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "metadata_test",
    srcs = ["metadata_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/common/dynamic_extensions:metadata_lib",
    ],
)
