load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_mock",
    "envoy_cc_test",
    "envoy_cc_test_library",
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
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/filesystem:filesystem_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test_library(
    name = "test_env_util_lib",
    srcs = ["test_env_util.cc"],
    hdrs = ["test_env_util.h"],
    data = [
        "@openssh_portable//:testdata_sshkey",
    ],
    repository = "@envoy",
    deps = [
        "//test/test_common:test_common_lib",
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

# envoy_cc_test(
#     name = "client_transport_test",
#     srcs = [
#         "client_transport_test.cc",
#     ],
#     repository = "@envoy",
#     deps = [
#         "//source/extensions/filters/network/ssh:pomerium_ssh",
#         "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
#         "@envoy//test/mocks/server:factory_context_mocks",
#     ],
# )

envoy_cc_test(
    name = "kex_test",
    srcs = [
        "kex_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
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
        ":test_env_util_lib",
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
    name = "frame_test",
    srcs = [
        "frame_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "transport_test",
    srcs = [
        "transport_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "version_exchange_test",
    srcs = [
        "version_exchange_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/buffer:buffer_mocks",
    ],
)

envoy_cc_test(
    name = "transport_base_test",
    srcs = [
        "transport_base_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_env_util_lib",
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
        "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
        "@envoy//test/mocks/buffer:buffer_mocks",
    ],
)
