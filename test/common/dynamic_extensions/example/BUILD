load("//bazel:dynamic_extension.bzl", "cc_dynamic_extension")

package(default_visibility = ["//visibility:public"])

cc_dynamic_extension(
    name = "example_extension",
    srcs = [
        "extension.cc",
    ],
    weak_deps = [
        "@envoy//envoy/server:factory_context_interface",
        "@envoy//source/common/filesystem:directory_lib",
        "@envoy//source/common/buffer:watermark_buffer_lib",
        "@envoy//source/common/runtime:runtime_lib",
    ],
)
