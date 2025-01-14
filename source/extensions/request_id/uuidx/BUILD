load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "pomerium_uuidx",
    srcs = [
        "config.cc",
    ],
    hdrs = [
        "config.h",
    ],
    repository = "@envoy",
    deps = [
        ":uuidx_cc_proto",
        "@envoy//envoy/http:request_id_extension_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:request_id_extension_config_interface",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//source/common/stream_info:stream_id_provider_lib",
        "@envoy//source/extensions/request_id/uuid:config",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/request_id/uuid/v3:pkg_cc_proto",
    ],
)

cc_proto_library(
    name = "uuidx_cc_proto",
    deps = ["//api/extensions/request_id/uuidx:uuidx_proto"],
)

envoy_cc_test(
    name = "uuidx_test",
    srcs = ["uuidx_test.cc"],
    repository = "@envoy",
    deps = [
        ":pomerium_uuidx",
        ":uuidx_cc_proto",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)
