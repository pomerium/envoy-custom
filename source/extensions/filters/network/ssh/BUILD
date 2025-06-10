load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "pomerium_ssh",
    srcs = [
        "extension_ping.cc",
        "frame.cc",
        "grpc_client_impl.cc",
        "kex.cc",
        "kex_alg.cc",
        "kex_alg_curve25519.cc",
        "openssh.cc",
        "packet_cipher.cc",
        "packet_cipher_aead.cc",
        "packet_cipher_etm.cc",
        "service_userauth.cc",
        "version_exchange.cc",
    ],
    hdrs = [
        "extension_ping.h",
        "frame.h",
        "grpc_client_impl.h",
        "kex.h",
        "kex_alg.h",
        "kex_alg_curve25519.h",
        "message_handler.h",
        "openssh.h",
        "packet_cipher.h",
        "packet_cipher_aead.h",
        "packet_cipher_etm.h",
        "service.h",
        "service_userauth.h",
        "transport.h",
        "transport_base.h",
        "version_exchange.h",
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
        "@envoy//source/common/event:deferred_task",
        "@envoy//source/common/grpc:async_client_lib",
        "@envoy//source/common/grpc:typed_async_client_lib",
        "@envoy//source/extensions/filters/network/generic_proxy/interface:codec_interface",
        "@envoy//source/extensions/filters/network/generic_proxy/interface:filter_interface",
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
