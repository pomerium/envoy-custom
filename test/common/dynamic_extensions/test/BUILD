load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("//bazel:dynamic_extension.bzl", "cc_dynamic_extension")

package(default_visibility = ["//visibility:public"])

cc_dynamic_extension(
    name = "test_optional_config",
    srcs = [
        "test_optional_config.cc",
    ],
)

cc_dynamic_extension(
    name = "test_required_config",
    srcs = [
        "test_required_config.cc",
    ],
)

cc_dynamic_extension(
    name = "test_no_config",
    srcs = [
        "test_no_config.cc",
    ],
)

cc_dynamic_extension(
    name = "test_no_config_2",
    srcs = [
        "test_no_config.cc",
    ],
)

cc_dynamic_extension(
    name = "test_no_init",
    srcs = [
        "test_no_init.cc",
    ],
)

cc_dynamic_extension(
    name = "test_md_unknown_keys",
    srcs = [
        "test_md_unknown_keys.cc",
    ],
)

cc_dynamic_extension(
    name = "test_no_metadata",
    srcs = [
        "test_no_metadata.cc",
    ],
)

cc_dynamic_extension(
    name = "test_no_id",
    srcs = [
        "test_no_id.cc",
    ],
)

cc_dynamic_extension(
    name = "test_invalid_id",
    srcs = [
        "test_invalid_id.cc",
    ],
)

cc_library(
    name = "missing_library",
    srcs = ["missing_library.cc"],
    hdrs = ["missing_library.h"],
)

cc_library(
    name = "invalid_version",
    srcs = ["invalid_version.cc"],
    hdrs = ["invalid_version.h"],
    linkstatic = True,
    alwayslink = True,
)

cc_dynamic_extension(
    name = "test_missing_symbol",
    srcs = [
        "test_missing_symbol.cc",
    ],
    weak_deps = [
        ":missing_library",
    ],
)

cc_dynamic_extension(
    name = "test_version_mismatch",
    srcs = [
        "test_version_mismatch.cc",
    ],
    weak_deps = [
        ":invalid_version",
    ],
)

cc_dynamic_extension(
    name = "test_tls",
    srcs = [
        "test_tls.cc",
    ],
)
