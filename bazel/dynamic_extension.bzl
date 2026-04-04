load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

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
        deps = weak_deps + ["//source/common/dynamic_extensions:cc_dynamic_extension_lib"],
        alwayslink = True,
    )
    cc_binary(
        name = name,
        srcs = [_name],
        copts = ["-fPIC"],
        linkopts = [
            "-fvisibility=hidden",
            "-fPIC",
        ],
        deps = ["//source/common/dynamic_extensions:cc_dynamic_extension_lib"],
        linkshared = True,
        linkstatic = False,
    )
