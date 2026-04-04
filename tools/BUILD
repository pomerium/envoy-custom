load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

cc_binary(
    name = "read-extension",
    srcs = ["read_extension.cc"],
    deps = [
        "//source/common/dynamic_extensions:metadata_lib",
        "@argparse",
    ],
)
