load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

# dependencies required for all extensions
builtin_host_deps = [
    "@envoy//envoy/server:instance_interface",
    "@envoy//source/common/common:logger_lib",
]

def _internal_api_deps_targets(targets):
    out = []
    for target in targets:
        out += [
            target + ":pkg_cc_proto_cc_proto",
            target + ":pkg_cc_proto_validate",
        ]
    return out

def cc_dynamic_extension(
        name,
        srcs = [],
        hdrs = [],
        copts = [],
        header_only_deps = [],
        internal_api_deps = [],
        host_deps = [],
        testonly = 0,
        visibility = ["//visibility:public"]):
    _name = "_" + name
    cc_library(
        name = _name,
        visibility = visibility,
        srcs = srcs + _internal_api_deps_targets(internal_api_deps),
        hdrs = hdrs,
        copts = copts + [
            "-fvisibility=hidden",
            "-fPIC",
        ],
        testonly = testonly,
        features = ["prefer_pic_for_opt_binaries"],
        linkstatic = True,
        deps = host_deps + builtin_host_deps + header_only_deps + [
            "@pomerium_envoy//source/common/dynamic_extensions:cc_dynamic_extension_lib",
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
        testonly = testonly,
        deps = ["@pomerium_envoy//source/common/dynamic_extensions:version_ref_lib"],
        linkshared = True,
        linkstatic = False,
    )
