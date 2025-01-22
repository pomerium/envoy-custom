load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cmake",
)

package(default_visibility = ["//visibility:public"])

envoy_cc_binary(
    name = "envoy",
    features = ["fully_static_link"],
    repository = "@envoy",
    stamped = True,
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//source/extensions/http/early_header_mutation/trace_context:pomerium_trace_context",
        "//source/extensions/request_id/uuidx:pomerium_uuidx",
        "//source/extensions/tracers/pomerium_otel",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_cmake(
    name = "libssh",
    cache_entries = {
        "BUILD_SHARED_LIBS": "off",
    },
    defines = ["LIBSSH_STATICLIB"],
    lib_source = "@libssh_mirror//:all",
    out_static_libs = ["libssh.a"],
)
