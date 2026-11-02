load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
)
load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("//bazel/ci/images:oci.bzl", "image")
load("//bazel/ci/license:license_stamp.bzl", "cc_license_stamp_lib")

package(default_visibility = ["//visibility:public"])

pomerium_extensions = [
    "//source/extensions/filters/network/ssh:pomerium_ssh",
    "//source/extensions/health_check/event_sinks/grpc:grpc_event_sink",
    "//source/extensions/http/early_header_mutation/trace_context:pomerium_trace_context",
    "//source/extensions/request_id/uuidx:pomerium_uuidx",
    "//source/extensions/tracers/pomerium_otel",
    "//source/extensions/transport_sockets/initial_metadata:pomerium_initial_metadata",
]

string_flag(
    name = "license_name",
    build_setting_default = "Apache-2.0",
    visibility = ["//visibility:public"],
)

cc_license_stamp_lib(
    name = "_license_stamp",
    license_name = ":license_name",
)

envoy_cc_binary(
    name = "envoy",
    linkopts = select({
        "@envoy//bazel:apple": [
            # https://github.com/envoyproxy/envoy/issues/24782
            "-Wl,-framework,CoreFoundation",
            # https://github.com/bazelbuild/bazel/pull/16414
            "-Wl,-undefined,error",
        ],
        "//conditions:default": [
            "-fPIE",
            "-Wl,-E",
            "-Wl,-z,relro,-z,now",
            "-Wl,--hash-style=gnu",
        ],
    }),
    repository = "@envoy",
    stamped = True,
    deps = pomerium_extensions + [
        "@envoy//source/exe:envoy_main_entry_lib",
    ] + select({
        "@platforms//os:linux": [
            "//source/extensions/bootstrap/dynamic_extension_loader",
        ],
        "//conditions:default": [],
    }) + [
        ":_license_stamp",
    ],
)

envoy_cc_binary(
    name = "envoy.static",
    features = select({
        "@platforms//os:macos": [],
        "@envoy//bazel:asan_build": [],
        "@envoy//bazel:tsan_build": [],
        "//conditions:default": ["fully_static_link"],
    }),
    repository = "@envoy",
    stamped = True,
    deps = pomerium_extensions + [
        "@envoy//source/exe:envoy_main_entry_lib",
    ] + [
        ":_license_stamp",
    ],
)

image(
    name = "envoy.image",
    srcs = [":envoy"],
    license_from = ":license_name",
    repository = "ghcr.io/pomerium/envoy-custom-debug",
)

image(
    name = "envoy.stripped.image",
    srcs = [":envoy.stripped"],
    license_from = ":license_name",
    repository = "ghcr.io/pomerium/envoy-custom",
)

image(
    name = "envoy.static.image",
    srcs = [":envoy.static"],
    license_from = ":license_name",
    repository = "ghcr.io/pomerium/envoy-custom-static-debug",
)

image(
    name = "envoy.static.stripped.image",
    srcs = [":envoy.static.stripped"],
    license_from = ":license_name",
    repository = "ghcr.io/pomerium/envoy-custom-static",
)

configure_make(
    name = "openssh_config_h",
    autoreconf = True,
    configure_in_place = True,
    configure_options = [
        "--disable-pkcs11",
        "--with-ssl-dir=$$EXT_BUILD_DEPS",
        "--without-zlib",
        "--with-sandbox=no",
    ],
    defines = [
        "WITH_OPENSSL=1",
    ],
    lib_source = "@openssh_portable//:all_sources",
    out_headers_only = True,
    postfix_script = """
        cp config.h $$INSTALLDIR/include
    """,
    targets = [
        "config.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//bazel:crypto",
        "@envoy//bazel:ssl",
    ],
)

refresh_compile_commands(
    name = "refresh_compile_commands",
    exclude_headers = "external",
    targets = {
        "//:envoy": "",
        "//test/...": "",
        "//tools/...": "",
    },
)
