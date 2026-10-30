load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc:defs.bzl", "cc_library")

def _license_stamp_src_impl(ctx):
    license_name_value = ctx.attr.license_name[BuildSettingInfo].value
    dst = ctx.actions.declare_file("license_stamp.cc")
    ctx.actions.write(
        output = dst,
        content = """
__attribute__((used, retain, section(".license"), aligned(1))) static const char pomerium_license_name[] = %r;\
""" % license_name_value,
    )
    return [DefaultInfo(
        files = depset(direct = [dst]),
    )]

_license_stamp_src = rule(
    implementation = _license_stamp_src_impl,
    attrs = {
        "license_name": attr.label(mandatory = True),
    },
)

def cc_license_stamp_lib(name, license_name, visibility = ["//visibility:public"]):
    _license_stamp_src(
        name = name + "_src",
        license_name = license_name,
    )
    cc_library(
        name = name,
        srcs = [name + "_src"],
        visibility = visibility,
        alwayslink = True,
        linkstatic = True,
    )
