load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "pomerium_ssh",
    srcs = [
        "kex_alg.cc",
        "kex_alg_curve25519.cc",
        "openssh.cc",
        "packet_cipher.cc",
        "packet_cipher_aead.cc",
    ],
    hdrs = [
        "kex_alg.h",
        "kex_alg_curve25519.h",
        "message_handler.h",
        "openssh.h",
        "packet_cipher.h",
        "packet_cipher_aead.h",
        "service.h",
    ],
    copts = [
        "-Wimplicit-fallthrough",
        "-Wimplicit-int-conversion",
        "-Wunsafe-buffer-usage",
    ],
    repository = "@envoy",
    deps = [
        ":ssh_cc_proto",
        ":ssh_common_lib",
        "//:openssh",
        "//source/common:common_lib",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:base64_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/common:utility_lib",
        "@envoy//source/common/crypto:utility_lib",
    ],
)

envoy_cc_library(
    name = "ssh_common_lib",
    srcs = [],
    hdrs = ["common.h"],
    repository = "@envoy",
    deps = [
        "//source/common:common_lib",
        "@envoy//source/common/common:fmt_lib",
        "@envoy//source/common/common:statusor_lib",
    ],
)

cc_proto_library(
    name = "ssh_cc_proto",
    deps = ["//api/extensions/filters/network/ssh:ssh_proto"],
)
