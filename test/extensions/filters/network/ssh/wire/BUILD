load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_benchmark_binary",
    "envoy_cc_mock",
    "envoy_cc_test",
    "envoy_cc_test_library",
)

envoy_cc_test(
    name = "encoding_test",
    srcs = ["encoding_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_mocks",
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_benchmark_binary(
    name = "encoding_bench_test",
    srcs = ["encoding_bench_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_github_google_benchmark//:benchmark",
    ],
)

envoy_cc_benchmark_binary(
    name = "messages_bench_test",
    srcs = ["messages_bench_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_github_google_benchmark//:benchmark",
    ],
)

envoy_cc_test(
    name = "messages_test",
    srcs = ["messages_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_mocks",
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test(
    name = "packet_test",
    srcs = ["packet_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_mocks",
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test(
    name = "field_test",
    srcs = ["field_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_mocks",
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//test/mocks/runtime:runtime_mocks",
        "@envoy//test/mocks/stream_info:stream_info_mocks",
        "@envoy//test/test_common:logging_lib",
    ],
)

envoy_cc_test(
    name = "util_test",
    srcs = ["util_test.cc"],
    repository = "@envoy",
    deps = [
        ":wire_test_util",
        "//source/extensions/filters/network/ssh/wire:wire_lib",
        "@com_google_absl//absl/random",
        "@envoy//source/common/common:random_generator_lib",
    ],
)

envoy_cc_test_library(
    name = "wire_test_util",
    srcs = [],
    hdrs = [
        "test_field_reflect.h",
        "test_util.h",
    ],
    repository = "@envoy",
    deps = [
        "//source/common:common_lib",
        "//source/extensions/filters/network/ssh/wire:wire_lib_common",
        "//test/test_common:test_common_lib",
        "@com_google_absl//absl/random",
    ],
)

envoy_cc_mock(
    name = "wire_test_mocks",
    srcs = [],
    hdrs = ["test_mocks.h"],
    repository = "@envoy",
    deps = [],
)
