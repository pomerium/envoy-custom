load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_cc_test",
    "envoy_cc_test_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test_library(
    name = "test_common",
    srcs = ["test_data.cc"],
    hdrs = [
        "test_config.h",
        "test_data.h",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//source/extensions/filters/network/ssh:ssh_cc_proto",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/filesystem:filesystem_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_mock(
    name = "test_mocks",
    srcs = ["test_mocks.cc"],
    hdrs = ["test_mocks.h"],
    repository = "@envoy",
    deps = [
        "//:openssh",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/filesystem:filesystem_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "packet_cipher_test",
    srcs = [
        "packet_cipher_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_common",
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
    ],
)

envoy_cc_test(
    name = "client_transport_test",
    srcs = [
        "client_transport_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_common",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "kex_test",
    srcs = [
        "kex_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_common",
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
        "@envoy//test/mocks/api:api_mocks",
    ],
)

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
        ":test_common",
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/test_common:environment_lib",
    ],
)
