def _multi_arch_transition_impl(_, __):
    return {
        "linux-amd64": {"//command_line_option:platforms": "//bazel/platforms/rbe:linux_x64"},
        "linux-arm64": {"//command_line_option:platforms": "//bazel/platforms/rbe:linux_arm64"},
        "macos-arm64": {"//command_line_option:platforms": "//bazel/platforms/rbe:macos"},
    }

multiarch_transition = transition(
    inputs = [],
    outputs = ["//command_line_option:platforms"],
    implementation = _multi_arch_transition_impl,
)

def _multiarch_envoy_cc_binary_impl(ctx):
    targets = ctx.split_attr.target
    return [DefaultInfo(
        files = depset(
            transitive = [
                targets["linux-amd64"][DefaultInfo].files,
                targets["linux-arm64"][DefaultInfo].files,
                targets["macos-arm64"][DefaultInfo].files,
            ],
        ),
    )]

multiarch_envoy_cc_binary = rule(
    attrs = {
        "target": attr.label(
            cfg = multiarch_transition,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    implementation = _multiarch_envoy_cc_binary_impl,
)
