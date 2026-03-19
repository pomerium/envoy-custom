load("@platforms//host:constraints.bzl", "HOST_CONSTRAINTS")
load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def luajit_copts():
    return [
        "-fPIC",
        "-DLJ_ARCH_HASFPU=1",
        "-DLJ_ABI_SOFTFP=0",
        "-DLUAJIT_UNWIND_EXTERNAL",
    ] + select(
        {
            "@pomerium_envoy//bazel/foreign_cc:luajit_target_x64": [
                "-DLUAJIT_TARGET=LUAJIT_ARCH_x64",
            ],
            "@pomerium_envoy//bazel/foreign_cc:luajit_target_arm64": [
                "-DLUAJIT_TARGET=LUAJIT_ARCH_arm64",
                "-fno-omit-frame-pointer",
            ],
        },
        # error messages set here are rather hard to notice by default
        no_match_error = "\n" +
                         "*******************************\n" +
                         "* luajit target arch not set! *\n" +
                         "*******************************",
    )

def _use_host_platform_impl(settings, _):
    target_platform = settings["//command_line_option:platforms"]
    set_target_arch = "x64" if "x86_64" in str(target_platform) else "arm64"
    return {
        "//command_line_option:platforms": "@platforms//host",
        "@pomerium_envoy//bazel/foreign_cc:luajit_target": set_target_arch,
    }

_use_host_platform = transition(
    inputs = ["//command_line_option:platforms"],
    outputs = ["//command_line_option:platforms", "@pomerium_envoy//bazel/foreign_cc:luajit_target"],
    implementation = _use_host_platform_impl,
)

def _use_target_platform_impl(settings, _):
    target_platform = settings["//command_line_option:platforms"]
    set_target_arch = "x64" if "x86_64" in str(target_platform) else "arm64"
    return {
        "@pomerium_envoy//bazel/foreign_cc:luajit_target": set_target_arch,
    }

_use_target_platform = transition(
    inputs = ["//command_line_option:platforms"],
    outputs = ["@pomerium_envoy//bazel/foreign_cc:luajit_target"],
    implementation = _use_target_platform_impl,
)

# this is mostly following the example at https://github.com/bazelbuild/examples/blob/main/configurations/cc_binary_selectable_copts/defs.bzl

def _lj_cc_binary_impl(ctx):
    binary = ctx.attr.target_binary if ctx.attr.target_binary else ctx.attr.host_binary
    outfile = ctx.actions.declare_file(ctx.label.name)
    cc_binary_outfile = binary[0][DefaultInfo].files.to_list()[0]

    ctx.actions.symlink(
        target_file = cc_binary_outfile,
        output = outfile,
    )
    return [
        DefaultInfo(
            executable = outfile,
            data_runfiles = binary[0][DefaultInfo].data_runfiles,
        ),
    ]

_lj_cc_binary = rule(
    attrs = {
        "target_binary": attr.label(
            allow_single_file = True,
            cfg = _use_target_platform,
        ),
        "host_binary": attr.label(
            allow_single_file = True,
            cfg = _use_host_platform,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    implementation = _lj_cc_binary_impl,
    executable = True,
)

def lj_cc_binary(name, host = False, **kwargs):
    if host:
        _lj_cc_binary(
            name = name,
            host_binary = "_" + name,
        )
    else:
        _lj_cc_binary(
            name = name,
            target_binary = "_" + name,
        )

    cc_binary(
        name = "_" + name,
        copts = luajit_copts(),
        **kwargs
    )

def _lj_cc_library_impl(ctx):
    library = ctx.attr.host_library if ctx.attr.host_library else ctx.attr.target_library
    return library[0][CcInfo]

_lj_cc_library = rule(
    implementation = _lj_cc_library_impl,
    attrs = {
        "host_library": attr.label(
            cfg = _use_host_platform,
        ),
        "target_library": attr.label(
            cfg = _use_target_platform,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

def lj_cc_library(name, host = False, **kwargs):
    if host:
        _lj_cc_library(
            name = name,
            host_library = "_" + name,
        )
    else:
        _lj_cc_library(
            name = name,
            target_library = "_" + name,
        )

    cc_library(
        name = "_" + name,
        copts = luajit_copts(),
        **kwargs
    )
