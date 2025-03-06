workspace(name = "pomerium_envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

envoy_version = "182e0dd26d878bc015a1286f2815676080cecf17"

openssh_version = "V_9_9_P1"

http_archive(
    name = "envoy",
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//patches/envoy:0001-revert-deps-drop-BoringSSL-linkstatic-patch-38621.patch",
        "//patches/envoy:0002-bump-dependencies.patch",
    ],
    sha256 = "b3a396974b06568ff0ab6528ad19ed02697a8402d822d0556815c5eba95edf6c",
    strip_prefix = "envoy-" + envoy_version,
    url = "https://github.com/envoyproxy/envoy/archive/" + envoy_version + ".zip",
)

local_repository(
    name = "envoy_build_config",
    path = "bazel/envoy_build_config",
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

load("@envoy_api//bazel:envoy_http_archive.bzl", "envoy_http_archive")

envoy_http_archive(
    name = "openssh_portable",
    build_file_content = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    locations = dict(
        openssh_portable = dict(
            license = "BSD",
            license_url = "https://github.com/openssh/openssh-portable/blob/master/LICENCE",
            project_name = "openssh-portable",
            sha256 = "fe3b5bb5087b516f9f0793b9b5f6289a34c44bd1ebd751b4cec93b97c80da112",
            strip_prefix = "openssh-portable-" + openssh_version,
            urls = ["https://github.com/openssh/openssh-portable/archive/" + openssh_version + ".zip"],
            version = "master",
        ),
    ),
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//patches/openssh:0001-openssh-libcrypto-rename.patch",
    ],
)
