load("@bazel_skylib//lib:selects.bzl", "selects")
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
        "linux_x64",
        "linux_arm64",
        "macos_arm64",
        "unset",
    ],
)

config_setting(
    name = "luajit_target_linux_x64",
    flag_values = {
        ":luajit_target": "linux_x64",
    },
    visibility = ["@luajit//:__pkg__"],
)

config_setting(
    name = "luajit_target_linux_arm64",
    flag_values = {
        ":luajit_target": "linux_arm64",
    },
    visibility = ["@luajit//:__pkg__"],
)

config_setting(
    name = "luajit_target_macos_arm64",
    flag_values = {
        ":luajit_target": "macos_arm64",
    },
    visibility = ["@luajit//:__pkg__"],
)

selects.config_setting_group(
    name = "luajit_target_x64",
    match_any = [
        "luajit_target_linux_x64",
    ],
    visibility = ["@luajit//:__pkg__"],
)

selects.config_setting_group(
    name = "luajit_target_arm64",
    match_any = [
        "luajit_target_linux_arm64",
        "luajit_target_macos_arm64",
    ],
    visibility = ["@luajit//:__pkg__"],
)

selects.config_setting_group(
    name = "luajit_target_linux",
    match_any = [
        "luajit_target_linux_x64",
        "luajit_target_linux_arm64",
    ],
    visibility = ["@luajit//:__pkg__"],
)

selects.config_setting_group(
    name = "luajit_target_macos",
    match_any = [
        "luajit_target_macos_arm64",
    ],
    visibility = ["@luajit//:__pkg__"],
)
