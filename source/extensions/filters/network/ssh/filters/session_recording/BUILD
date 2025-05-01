load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

envoy_cc_library(
    name = "session_recording_filter",
    srcs = [
        "admin_api.cc",
        "config.cc",
        "formatter.cc",
        "recorder.cc",
        "uploader.cc",
    ],
    hdrs = [
        "admin_api.h",
        "config.h",
        "formatter.h",
        "formatter_asciicast.h",
        "formatter_raw.h",
        "recorder.h",
        "uploader.h",
    ],
    copts = [
        "-Wimplicit-fallthrough",
        "-Wimplicit-int-conversion",
        "-Wunsafe-buffer-usage",
    ],
    repository = "@envoy",
    deps = [
        ":session_recording_cc_proto",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//source/extensions/filters/network/ssh/filters/session_recording/web:assets",
        "@envoy//envoy/compression/compressor:compressor_config_interface",
        "@envoy//envoy/compression/compressor:compressor_factory_interface",
        "@envoy//envoy/compression/compressor:compressor_interface",
        "@envoy//source/common/json:json_streamer_lib",
        "@envoy//source/common/runtime:runtime_lib",
        "@envoy//source/extensions/filters/network/generic_proxy/interface:filter_interface",
    ],
)

cc_proto_library(
    name = "session_recording_cc_proto",
    deps = ["//api/extensions/filters/network/ssh/filters/session_recording:session_recording_proto"],
)
