load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
)

package(default_visibility = ["//visibility:public"])

envoy_cc_binary(
    name = "envoy",
    features = ["fully_static_link"],
    repository = "@envoy",
    deps = [
        "//source/extensions/http/early_header_mutation/trace_context:pomerium_trace_context",
        "//source/extensions/request_id/uuidx:pomerium_uuidx",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
