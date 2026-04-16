load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load("@rules_cc//cc:cc_library.bzl", "cc_library")

jq(
    name = "_version_hash_h",
    srcs = ["//bazel/build_info:combined_status"],
    out = "version_hash.h",
    args = ["-r"],
    filter = r'"#pragma once\n#define POMERIUM_ENVOY_VERSION \(.STABLE_BUILD_SCM_REVISION)"',
    visibility = ["//visibility:private"],
)

cc_library(
    name = "metadata_lib",
    srcs = ["metadata.cc"],
    hdrs = ["metadata.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//source/common:common_lib",
    ],
)

cc_library(
    name = "version_lib",
    hdrs = [
        "version.h",
        ":_version_hash_h",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "extension_common_lib",
    srcs = [
        "extension.h",
        "factory.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//source/common:common_lib",
    ],
)

cc_library(
    name = "extension_host_lib",
    srcs = [
        "version.cc",
    ],
    linkstatic = True,
    visibility = ["//source/extensions/bootstrap/dynamic_extension_loader:__pkg__"],
    deps = [
        ":extension_common_lib",
        ":metadata_lib",
        ":version_lib",
        "@envoy//envoy/server:instance_interface",
    ],
    alwayslink = True,
)

cc_library(
    name = "version_ref_lib",
    srcs = ["version_ref.cc"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [":version_lib"],
    alwayslink = True,
)

cc_library(
    name = "cc_dynamic_extension_lib",
    srcs = [
        "version.cc",
    ],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":extension_common_lib",
        ":version_lib",
    ],
    alwayslink = True,
)
