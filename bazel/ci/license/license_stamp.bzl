load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc:defs.bzl", "cc_library")

_src_templates = {
    "linux": r'__attribute__((used, retain, section(".license"), aligned(1))) static const char pomerium_license_name[] = %r;',
    "darwin": r'__attribute__((used, retain, section("__TEXT,__license"), aligned(1))) static const char pomerium_license_name[] = %r;',
}

def _license_stamp_src_impl(ctx):
    license_name_value = ctx.attr.license_name[BuildSettingInfo].value
    dst = ctx.actions.declare_file("license_stamp.cc")

    ctx.actions.write(
        output = dst,
        content = _src_templates[ctx.attr.os] % license_name_value,
    )
    return [DefaultInfo(
        files = depset(direct = [dst]),
    )]

_license_stamp_src = rule(
    implementation = _license_stamp_src_impl,
    attrs = {
        "license_name": attr.label(mandatory = True),
        "os": attr.string(mandatory = True, values = _src_templates.keys()),
    },
)

def cc_license_stamp_lib(name, license_name, visibility = ["//visibility:public"]):
    _license_stamp_src(
        name = name + "_src",
        license_name = license_name,
        os = select({
            "@platforms//os:linux": "linux",
            "@platforms//os:macos": "darwin",
        }),
    )
    cc_library(
        name = name,
        srcs = [name + "_src"],
        visibility = visibility,
        alwayslink = True,
        linkstatic = True,
    )
