load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

envoy_cc_test(
    name = "status_test",
    srcs = [
        "factory_test.cc",
        "fixed_string_test.cc",
        "span_test.cc",
        "status_test.cc",
        "type_traits_test.cc",
        "visit_test.cc",
    ],
    repository = "@envoy",
    deps = [
        "//source/common:common_lib",
        "//test/test_common:test_common_lib",
    ],
)
