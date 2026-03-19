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
            ],
        },
        # error messages set here are rather hard to notice by default
        no_match_error = "\n" +
                         "*******************************\n" +
                         "* luajit target arch not set! *\n" +
                         "*******************************",
    )

def _get_host_platform():
    if "@platforms//cpu:x86_64" in HOST_CONSTRAINTS:
        return "x64"
    elif "@platforms//cpu:arm64" in HOST_CONSTRAINTS:
        return "arm64"
    else:
        fail("unknown host platform: %s" % HOST_CONSTRAINTS)

_platform_mappings = {
    "linux_x64": "x64",
    "linux_x86_64": "x64",
    "linux_arm64": "arm64",
    "linux_aarch64": "arm64",
    "macos_arm64": "arm64",
    "macos_aarch64": "arm64",
}

def _use_host_platform_impl(settings, _):
    existing_target = settings["@pomerium_envoy//bazel/foreign_cc:luajit_target"]
    if existing_target and existing_target != "unset":
        print("found an existing luajit_target, not modifying it: %s" % existing_target)
        return {
            "//command_line_option:platforms": "@platforms//host",
            "@pomerium_envoy//bazel/foreign_cc:luajit_target": existing_target,
        }
    target_platform = Label(settings["//command_line_option:platforms"][0]).name
    print("target_platform: %s" % target_platform)
    if target_platform in _platform_mappings:
        set_target_arch = _platform_mappings[target_platform]
    else:
        print("using host platform")
        set_target_arch = _get_host_platform()
    print("set_target_arch: %s" % set_target_arch)

    return {
        "//command_line_option:platforms": "@platforms//host",
        "@pomerium_envoy//bazel/foreign_cc:luajit_target": set_target_arch,
    }

_use_host_platform = transition(
    inputs = ["//command_line_option:platforms", "@pomerium_envoy//bazel/foreign_cc:luajit_target"],
    outputs = ["//command_line_option:platforms", "@pomerium_envoy//bazel/foreign_cc:luajit_target"],
    implementation = _use_host_platform_impl,
)

def _use_target_platform_impl(settings, _):
    target_platform = Label(settings["//command_line_option:platforms"][0]).name
    print("target_platform: %s" % target_platform)
    if target_platform in _platform_mappings:
        set_target_arch = _platform_mappings[target_platform]
    else:
        print("using host platform")
        set_target_arch = _get_host_platform()
    print("set_target_arch: %s" % set_target_arch)

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
    print("lj_cc_binary: %s" % name)
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
