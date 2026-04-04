load("@aspect_bazel_lib//lib:jq.bzl", "jq")
load("@rules_cc//cc:cc_library.bzl", "cc_library")

global_versioned_symbols = [
    "pomerium_envoy_version",
    "_Z20dynamicExtensionInitRN5Envoy6Server8InstanceE",
]

jq(
    name = "_version_script",
    srcs = ["//bazel/build_info:volatile_status"],
    out = "version.lds",
    args = ["-r"],
    filter = r'"\(.BUILD_SCM_HASH) { global: %s; };"' % ";".join(global_versioned_symbols),
    visibility = ["//visibility:private"],
)

jq(
    name = "_version_h",
    srcs = ["//bazel/build_info:volatile_status"],
    out = "version.h",
    args = ["-r"],
    filter = r'"#pragma once\n#define POMERIUM_BUILD_HASH \"\(.BUILD_SCM_HASH)\""',
    visibility = ["//visibility:private"],
)

cc_library(
    name = "extension_api_lib",
    hdrs = [
        "handle.h",
        ":_version_h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":metadata_lib",
        "@envoy//envoy/server:instance_interface",
    ],
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
    srcs = ["version.cc"],
    hdrs = [":_version_h"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    alwayslink = True,
)

cc_library(
    name = "cc_dynamic_extension_lib",
    hdrs = ["extension.h"],
    additional_linker_inputs = [":_version_script"],
    linkopts = ["-Wl,--version-script=$(location :_version_script)"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [":version_lib"],
    alwayslink = True,
)
