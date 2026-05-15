load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

exports_files(
    ["check_macos_tcmalloc_symbols.sh"],
    visibility = ["//visibility:public"],
)

cc_binary(
    name = "read-extension",
    srcs = ["read_extension.cc"],
    visibility = ["//visibility:public"],
    deps = [
        "//source/common/dynamic_extensions:extension_common_lib",
        "//source/common/dynamic_extensions:metadata_lib",
        "@argparse",
    ],
)
