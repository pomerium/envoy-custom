load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

envoy_cc_library(
    name = "assets",
    srcs = [":generate_assets"],
    hdrs = ["assets.h"],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        ":generate_assets",
    ],
)

genrule(
    name = "generate_assets",
    srcs = [
        "asciinema_player.min.js",
        "asciinema_player.css",
        "index.html",
    ],
    outs = ["assets.cc"],
    cmd = "./$(location :generate.sh) $(location asciinema_player.min.js) $(location asciinema_player.css) $(location index.html) > $@",
    tools = [":generate.sh"],
)
