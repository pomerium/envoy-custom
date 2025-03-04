workspace(name = "pomerium_envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

envoy_version = "1.33.0"

http_archive(
    name = "envoy",
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [],
    sha256 = "f9e0d838eff2a3e8ede4273313db592aada4392d85865d7b2ce752fbd9da3591",
    strip_prefix = "envoy-" + envoy_version,
    url = "https://github.com/envoyproxy/envoy/archive/refs/tags/v" + envoy_version + ".zip",
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
            sha256 = "c017ff52d6e3e53fceae4cb2685f02ac8f0f04807296f1ba12806cf9c3e58db2",
            strip_prefix = "openssh-portable-V_9_9_P2",
            urls = ["https://github.com/openssh/openssh-portable/archive/refs/tags/V_9_9_P2.zip"],
            version = "V_9_9_P2",
        ),
    ),
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//:patches/0001-openssh-libcrypto-rename.patch",
    ],
)
