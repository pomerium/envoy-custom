load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

# dependencies required for all extensions
builtin_weak_deps = [
    "@envoy//envoy/server:instance_interface",
    "@envoy//source/common/common:logger_lib",
]

def cc_dynamic_extension(
        name,
        srcs = [],
        hdrs = [],
        copts = [],
        weak_deps = [],
        visibility = ["//visibility:public"]):
    _name = "_" + name
    cc_library(
        name = _name,
        visibility = visibility,
        srcs = srcs,
        hdrs = hdrs,
        copts = copts + [
            "-fvisibility=hidden",
            "-fPIC",
        ],
        features = ["prefer_pic_for_opt_binaries"],
        linkstatic = True,
        deps = weak_deps + builtin_weak_deps + [
            "//source/common/dynamic_extensions:cc_dynamic_extension_lib",
        ],
        alwayslink = True,
    )
    cc_binary(
        name = name,
        srcs = [_name],
        linkopts = [
            "-fvisibility=hidden",
            "-fPIC",
        ],
        deps = ["//source/common/dynamic_extensions:version_ref_lib"],
        linkshared = True,
        linkstatic = False,
    )
