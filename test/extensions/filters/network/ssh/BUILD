load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_benchmark_binary",
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
        "@envoy//test/mocks/stats:stats_mocks",
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
    name = "extension_ping_test",
    srcs = [
        "extension_ping_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
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
    name = "kex_alg_mlkem_test",
    srcs = [
        "kex_alg_mlkem_test.cc",
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

envoy_cc_test(
    name = "packet_cipher_etm_test",
    srcs = [
        "packet_cipher_etm_test.cc",
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
    name = "service_connection_test",
    srcs = [
        "service_connection_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/mocks/event:event_mocks",
        "@envoy//test/mocks/grpc:grpc_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "service_userauth_test",
    srcs = [
        "service_userauth_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_env_util_lib",
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/api:api_mocks",
        "@envoy//test/test_common:utility_lib",
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
    name = "kex_test",
    size = "large",
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
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "server_transport_test",
    srcs = [
        "server_transport_test.cc",
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
        "@envoy//test/mocks/grpc:grpc_mocks",
        "@envoy//test/mocks/network:connection_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "client_transport_test",
    srcs = [
        "client_transport_test.cc",
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
        "@envoy//test/mocks/network:connection_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "config_test",
    srcs = [
        "config_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_env_util_lib",
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
        "@envoy//test/extensions/filters/network/generic_proxy/mocks:codec_mocks",
        "@envoy//test/mocks/server:factory_context_mocks",
    ],
)

envoy_cc_test(
    name = "stream_tracker_test",
    srcs = [
        "stream_tracker_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/server:factory_context_mocks",
        "@envoy//test/test_common:real_threads_test_helper_lib",
    ],
)

envoy_cc_test(
    name = "id_manager_test",
    srcs = [
        "id_manager_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":test_mocks",
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "filter_state_objects_test",
    srcs = [
        "filter_state_objects_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "socks5_test",
    srcs = [
        "socks5_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
    ],
)

envoy_cc_test(
    name = "stream_address_test",
    srcs = [
        "stream_address_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
        "@envoy//test/mocks/event:event_mocks",
    ],
)

envoy_cc_test_library(
    name = "integration_lib",
    srcs = [
        "ssh_connection_driver.cc",
        "ssh_integration_test.cc",
    ],
    hdrs = [
        "ssh_connection_driver.h",
        "ssh_integration_test.h",
        "ssh_task.h",
    ],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/extensions/filters/network/ssh/wire:wire_test_util",
        "//test/test_common:test_common_lib",
        "@envoy//source/extensions/filters/http/set_filter_state:config",
        "@envoy//source/extensions/filters/network/generic_proxy:config",
        "@envoy//source/extensions/filters/network/generic_proxy/router:config",
        "@envoy//source/extensions/filters/network/set_filter_state:config",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "@envoy//source/extensions/transport_sockets/internal_upstream:config",
        "@envoy//test/integration:http_integration_lib",
    ],
)

envoy_cc_test(
    name = "reverse_tunnel_test",
    size = "large",
    srcs = [
        "reverse_tunnel_test.cc",
    ],
    repository = "@envoy",
    deps = [
        ":integration_lib",
    ],
)

envoy_cc_benchmark_binary(
    name = "packet_cipher_bench_test",
    srcs = ["packet_cipher_bench_test.cc"],
    repository = "@envoy",
    deps = [
        "//source/extensions/filters/network/ssh:pomerium_ssh",
        "//test/test_common:test_common_lib",
        "@com_github_google_benchmark//:benchmark",
    ],
)
