load("@bazel_skylib//rules:common_settings.bzl", "string_flag")

exports_files(["openssh.BUILD"])

alias(
    name = "luajit",
    actual = "@luajit//:luajit",
)

alias(
    name = "luajit_host_buildvm",
    actual = "@luajit//:host_buildvm",
)

string_flag(
    name = "luajit_target",
    build_setting_default = "unset",
    values = [
        "x64",
        "arm64",
        "unset",
    ],
)

config_setting(
    name = "luajit_target_x64",
    flag_values = {
        ":luajit_target": "x64",
    },
    visibility = ["@luajit//:__pkg__"],
)

config_setting(
    name = "luajit_target_arm64",
    flag_values = {
        ":luajit_target": "arm64",
    },
    visibility = ["@luajit//:__pkg__"],
)
