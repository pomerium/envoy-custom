# Contains select upstream tests to run for code that may be affected by our patches

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_package",
)

envoy_package()

test_suite(
    name = "lua_tests",
    tests = [
        "@envoy//test/extensions/filters/http/lua:config_test",
        "@envoy//test/extensions/filters/http/lua:lua_filter_test",
        "@envoy//test/extensions/filters/http/lua:wrappers_test",
    ],
)
