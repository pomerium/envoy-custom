load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

# dependencies required for all extensions
builtin_host_deps = [
    "@envoy//envoy/server:instance_interface",
    "@envoy//source/common/common:logger_lib",
]

def _filter_static_libs_impl(ctx):
    linker_inputs = []
    for src in ctx.attr.srcs:
        if DefaultInfo in src:
            files = src[DefaultInfo].files.to_list()
            generated_libs = [
                cc_common.create_library_to_link(pic_static_library = f, actions = ctx.actions)
                for f in files
                if f.extension == "a"
            ]
            linker_inputs.append(cc_common.create_linker_input(
                owner = src.label,
                libraries = depset(direct = generated_libs),
            ))

    return [
        CcInfo(
            linking_context = cc_common.create_linking_context(
                linker_inputs = depset(direct = linker_inputs),
            ),
        ),
    ]

def _filter_generated_hdrs_impl(ctx):
    generated_hdrs = []
    for src in ctx.attr.srcs:
        if DefaultInfo in src:
            files = src[DefaultInfo].files.to_list()
            generated_hdrs += [f for f in files if f.extension == "h"]
    return [
        DefaultInfo(
            files = depset(direct = generated_hdrs),
        ),
    ]

_filter_static_libs = rule(
    implementation = _filter_static_libs_impl,
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
        ),
    },
)

_filter_generated_hdrs = rule(
    implementation = _filter_generated_hdrs_impl,
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
        ),
    },
)

_disable_fission_transition = transition(
    implementation = lambda _, __: {"//command_line_option:fission": "no"},
    inputs = [],
    outputs = ["//command_line_option:fission"],
)

def _extension_cc_binary_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".so")
    ctx.actions.symlink(
        target_file = ctx.attr.target[0][DefaultInfo].files.to_list()[0],
        output = output,
    )
    return [
        DefaultInfo(
            files = depset(direct = [output]),
        ),
    ]

extension_cc_binary = rule(
    implementation = _extension_cc_binary_impl,
    attrs = {
        "target": attr.label(
            allow_single_file = True,
            cfg = _disable_fission_transition,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

def _internal_api_deps_targets(targets):
    out = []
    for target in targets:
        # TODO: handle grpc services
        out += [
            target + ":pkg_cc_proto_cc_proto",
            target + ":pkg_cc_proto_validate",
            target + ":pkg_cc_proto_descriptor",
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
    _filter_static_libs(
        name = _name + "_proto_generated_libs",
        srcs = _internal_api_deps_targets(internal_api_deps),
        testonly = testonly,
    )
    _filter_generated_hdrs(
        name = _name + "_proto_generated_hdrs",
        srcs = _internal_api_deps_targets(internal_api_deps),
        testonly = testonly,
    )
    cc_library(
        name = _name + "_lib",
        visibility = visibility,
        srcs = srcs,
        hdrs = hdrs + [_name + "_proto_generated_hdrs"],
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
        name = _name,
        srcs = [_name + "_lib"],
        linkopts = [
            "-fvisibility=hidden",
            "-fPIC",
        ],
        testonly = testonly,
        deps = [
            "@pomerium_envoy//source/common/dynamic_extensions:version_ref_lib",

            # We use the envoy macros to build protobuf packages, which expand to several other
            # rules. The combined output is the generated headers plus several libraries (both .a
            # and .so versions for each), and the generated sources used to build those libraries.
            # If the symbols for the generated code aren't in the host binary, they all need to be
            # in the extension binary. Since the extension is a shared library, directly depending
            # on the *_cc_proto target will link with shared library built from the generated code
            # instead of the static one. This forces it to link only the static libraries instead.
            # Note that this has to be added here and not part of the srcs of the cc_library above,
            # which is where the extension sources normally go. Adding the proto targets there will
            # cause an internal error in bazel.
            _name + "_proto_generated_libs",
        ],
        linkshared = True,
        linkstatic = False,
    )
    extension_cc_binary(
        name = name,
        target = _name,
        testonly = testonly,
    )
