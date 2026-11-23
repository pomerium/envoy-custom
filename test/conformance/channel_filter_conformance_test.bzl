load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_test")

def channel_filter_conformance_test(
        name,
        extension,
        config):
    envoy_cc_test(
        name = "channel_filter_conformance_test_" + name,
        linkopts = [
            "-Wl,-E",
        ],
        repository = "@envoy",
        data = [extension],
        deps = [
            config,
            "@pomerium_envoy//test/conformance:channel_filter_conformance_test",
            "@pomerium_envoy//source/extensions/bootstrap/dynamic_extension_loader",
            Label(extension).relative("_%s_deps_lib" % Label(extension).name),
        ],
    )
