load("@aspect_bazel_lib//lib:paths.bzl", "BASH_RLOCATION_FUNCTION", "to_rlocation_path")

def _impl(ctx):
    if not ctx.file.image.is_directory:
        fail("image attribute must be a oci_image or oci_image_index")

    crane = ctx.attr._crane[platform_common.ToolchainInfo]
    jq = ctx.attr._jq[platform_common.ToolchainInfo]
    executable = ctx.actions.declare_file("update_index_%s.sh" % ctx.label.name)
    substitutions = {
        "{{BASH_RLOCATION_FUNCTION}}": BASH_RLOCATION_FUNCTION,
        "{{crane_path}}": to_rlocation_path(ctx, crane.crane_info.binary),
        "{{jq_path}}": to_rlocation_path(ctx, jq.jqinfo.bin),
        "{{manifest_digest_file}}": to_rlocation_path(ctx, ctx.file.manifest_digest),
        "{{index_tags_file}}": to_rlocation_path(ctx, ctx.file.index_tags),
        "{{image_dir}}": to_rlocation_path(ctx, ctx.file.image),
        "{{repository}}": ctx.attr.repository,
    }

    ctx.actions.expand_template(
        template = ctx.file._update_index_sh_tpl,
        output = executable,
        is_executable = True,
        substitutions = substitutions,
    )

    runfiles = ctx.runfiles(
        files = [
            ctx.file.image,
            ctx.file.manifest_digest,
            ctx.file.index_tags,
        ],
    )
    runfiles = runfiles.merge(crane.default.default_runfiles)
    runfiles = runfiles.merge(jq.default.default_runfiles)
    runfiles = runfiles.merge(ctx.attr.image[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.attr._runfiles.default_runfiles)
    return DefaultInfo(executable = executable, runfiles = runfiles)

oci_update_index = rule(
    implementation = _impl,
    attrs = {
        "repository": attr.string(
            mandatory = True,
        ),
        "image": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "manifest_digest": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "index_tags": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "_crane": attr.label(
            default = "@oci_crane_toolchains//:current_toolchain",
            cfg = "exec",
        ),
        "_update_index_sh_tpl": attr.label(
            default = "update_index.sh.tpl",
            allow_single_file = True,
        ),
        "_runfiles": attr.label(
            default = "@bazel_tools//tools/bash/runfiles",
        ),
        "_jq": attr.label(
            default = "@jq_toolchains//:resolved_toolchain",
            cfg = "exec",
        ),
    },
    toolchains = ["@bazel_tools//tools/sh:toolchain_type"],
    executable = True,
)
