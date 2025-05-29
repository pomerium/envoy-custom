load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_mock(
    name = "test_mocks",
    srcs = ["test_mocks.cc"],
    hdrs = ["test_mocks.h"],
    repository = "@envoy",
    deps = [
        "//:openssh",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
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
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/test_common:environment_lib",
    ],
)

envoy_cc_test(
    name = "packet_cipher_test",
    srcs = [
        "packet_cipher_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
    ],
)

envoy_cc_test(
    name = "kex_alg_test",
    srcs = [
        "kex_alg_test.cc",
    ],
    data = [
        "@openssh_portable//:testdata_sshkey",
    ],
    repository = "@envoy",
    deps = [
        "//:openssh",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/test_common:environment_lib",
    ],
)

envoy_cc_test(
    name = "message_handler_test",
    srcs = [
        "message_handler_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "grpc_client_impl_test",
    srcs = [
        "grpc_client_impl_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/grpc:grpc_mocks",
    ],
)

envoy_cc_test(
    name = "kex_alg_curve25519_test",
    srcs = [
        "kex_alg_curve25519_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "packet_cipher_aead_test",
    srcs = [
        "packet_cipher_aead_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//:openssh",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/test_common:environment_lib",
    ],
)
