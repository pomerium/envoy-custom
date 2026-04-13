load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
)
load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("//bazel/ci/images:oci.bzl", "image")

package(default_visibility = ["//visibility:public"])

pomerium_extensions = [
    "//source/extensions/filters/network/ssh:pomerium_ssh",
    "//source/extensions/health_check/event_sinks/grpc:grpc_event_sink",
    "//source/extensions/http/early_header_mutation/trace_context:pomerium_trace_context",
    "//source/extensions/request_id/uuidx:pomerium_uuidx",
    "//source/extensions/tracers/pomerium_otel",
]

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
    }),
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
    ],
)

image(
    name = "envoy.image",
    srcs = [":envoy"],
    repository = "ghcr.io/pomerium/envoy-custom-debug",
)

image(
    name = "envoy.stripped.image",
    srcs = [":envoy.stripped"],
    repository = "ghcr.io/pomerium/envoy-custom",
)

image(
    name = "envoy.static.image",
    srcs = [":envoy.static"],
    repository = "ghcr.io/pomerium/envoy-custom-static-debug",
)

image(
    name = "envoy.static.stripped.image",
    srcs = [":envoy.static.stripped"],
    repository = "ghcr.io/pomerium/envoy-custom-static",
)

configure_make(
    name = "legacy_openssh",
    args = ["-j4"],
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
    env = select({
        "@platforms//os:macos": {"AR": ""},
        "//conditions:default": {},
    }),
    includes = [
        "openssh",
    ],
    lib_source = "@openssh_portable//:all_sources",
    linkopts = ["-pthread"],
    out_static_libs = [
        "libssh.a",
        "libopenbsd-compat.a",
    ],
    postfix_script = """
        cp -L libssh.a $$INSTALLDIR/lib && \
        cp -L openbsd-compat/libopenbsd-compat.a $$INSTALLDIR/lib && \
        rm -rf $$INSTALLDIR/include/openssh && \
        mkdir -p $$INSTALLDIR/include/openssh/openbsd-compat && \
        cp -L *.h $$INSTALLDIR/include/openssh && \
        cp -L openbsd-compat/*.h $$INSTALLDIR/include/openssh/openbsd-compat
    """,
    set_file_prefix_map = True,
    targets = [
        "",
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
