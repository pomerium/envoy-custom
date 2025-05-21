load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "openssh_test",
    srcs = [
        "openssh_test.cc",
    ],
    data = [
        "@openssh_portable//:testdata_sshkey",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/test_common:environment_lib",
    ],
)
