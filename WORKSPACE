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
    name = "libssh_mirror",
    build_file_content = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    locations = dict(
        libssh_mirror = dict(
            license = "LGPL-2.1",
            license_url = "https://gitlab.com/libssh/libssh-mirror/-/raw/master/COPYING?inline=false",
            project_name = "libssh-mirror",
            sha256 = "b43ef9c91b6c3db64e7ba3db101eb89dbe645db63489c19d4f88cf6f84911ec6",
            strip_prefix = "libssh-mirror-libssh-0.11.1",
            urls = ["https://gitlab.com/libssh/libssh-mirror/-/archive/libssh-0.11.1/libssh-mirror-libssh-0.11.1.tar.gz"],
            version = "0.11.1",
        ),
    ),
)
