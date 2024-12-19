workspace(name = "pomerium_envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "envoy",
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//:patches/0001-fix-otel-grpc-trace-exporter.patch",
    ],
    strip_prefix = "envoy-1.32.2",
    url = "https://github.com/envoyproxy/envoy/archive/refs/tags/v1.32.2.zip",
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
