load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "dynamic_extension_loader",
    srcs = [
        "config.cc",
        "loader.cc",
    ],
    hdrs = [
        "config.h",
        "loader.h",
    ],
    repository = "@envoy",
    deps = [
        "//api/extensions/bootstrap/dynamic_extension_loader:pkg_cc_proto",
        "//source/common:common_lib",
        "//source/common/dynamic_extensions:extension_api_lib",
        "//source/common/dynamic_extensions:version_lib",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:bootstrap_extension_config_interface",
        "@envoy//envoy/server:factory_context_interface",
        "@envoy//envoy/server:instance_interface",
        "@envoy//source/common/filesystem:directory_lib",
    ],
)
