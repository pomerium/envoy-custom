load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
)

envoy_cc_test(
    name = "common_test",
    srcs = [
        "bytes_view_test.cc",
        "factory_test.cc",
        "id_alloc_test.cc",
        "math_test.cc",
        "span_test.cc",
        "static_error_test.cc",
        "static_string_test.cc",
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
