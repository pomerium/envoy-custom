load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
)
load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")
load("@rules_foreign_cc//foreign_cc:make.bzl", "make")

package(default_visibility = ["//visibility:public"])

envoy_cc_binary(
    name = "envoy",
    features = select({
        "@platforms//os:macos": [],
        "@envoy//bazel:asan_build": [],
        "//conditions:default": ["fully_static_link"],
    }),
    repository = "@envoy",
    stamped = True,
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//source/extensions/filters/network/ssh/filters/session_recording:session_recording_filter",
        "//source/extensions/http/early_header_mutation/trace_context:pomerium_trace_context",
        "//source/extensions/request_id/uuidx:pomerium_uuidx",
        "//source/extensions/tracers/pomerium_otel",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

configure_make(
    name = "openssh",
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
    lib_source = "@openssh_portable//:all",
    out_static_libs = [
        "libssh.a",
        "libopenbsd-compat.a",
    ],
    postfix_script = """
        cp -L libssh.a $INSTALLDIR/lib && \
        cp -L openbsd-compat/libopenbsd-compat.a $INSTALLDIR/lib && \
        rm -rf $INSTALLDIR/include/openssh && \
        mkdir -p $INSTALLDIR/include/openssh/openbsd-compat && \
        cp -L *.h $INSTALLDIR/include/openssh && \
        cp -L openbsd-compat/*.h $INSTALLDIR/include/openssh/openbsd-compat &&
    """,
    set_file_prefix_map = True,
    targets = [
        "",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//bazel:boringcrypto",
        "@envoy//bazel:boringssl",
    ],
)

make(
    name = "libvterm",
    env = {
        "INCDIR": "libvterm",
    },
    lib_source = "@libvterm//:all",
    out_static_libs = [
        "libvterm.a",
    ],
    postfix_script = """
        cp -L src/utf8.h $INSTALLDIR/include && \
        mkdir -p $INSTALLDIR/include/libvterm && \
        mv -f $INSTALLDIR/include/*.h $INSTALLDIR/include/libvterm/
    """,
    set_file_prefix_map = True,
    targets = [
        "libvterm.a",
        "install-inc",
        "install-lib",
    ],
    visibility = ["//visibility:public"],
)

refresh_compile_commands(
    name = "refresh_compile_commands",
    exclude_headers = "external",
    targets = {
        "//:envoy": "",
        "//test/...": "",
    },
)
