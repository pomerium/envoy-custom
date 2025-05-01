workspace(name = "pomerium_envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Hedron's Compile Commands Extractor for Bazel
# https://github.com/hedronvision/bazel-compile-commands-extractor
http_archive(
    name = "hedron_compile_commands",
    strip_prefix = "bazel-compile-commands-extractor-f5fbd4cee671d8d908f37c83abaf70fba5928fc7",
    url = "https://github.com/mikael-s-persson/bazel-compile-commands-extractor/archive/f5fbd4cee671d8d908f37c83abaf70fba5928fc7.tar.gz",
)

load("@hedron_compile_commands//:workspace_setup.bzl", "hedron_compile_commands_setup")

hedron_compile_commands_setup()

load("@hedron_compile_commands//:workspace_setup_transitive.bzl", "hedron_compile_commands_setup_transitive")

hedron_compile_commands_setup_transitive()

load("@hedron_compile_commands//:workspace_setup_transitive_transitive.bzl", "hedron_compile_commands_setup_transitive_transitive")

hedron_compile_commands_setup_transitive_transitive()

load("@hedron_compile_commands//:workspace_setup_transitive_transitive_transitive.bzl", "hedron_compile_commands_setup_transitive_transitive_transitive")

hedron_compile_commands_setup_transitive_transitive_transitive()

envoy_version = "77a4c7abbbe698e78f8be9c16e80dee189b4fea3"

openssh_version = "V_9_9_P1"

magic_enum_version = "a413fcc9c46a020a746907136a384c227f3cd095"

http_archive(
    name = "envoy",
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//patches/envoy:0001-revert-deps-drop-BoringSSL-linkstatic-patch-38621.patch",
        "//patches/envoy:0002-bump-dependencies.patch",
        "//patches/envoy:tmp-fix-upstream-connection-callbacks.patch",
    ],
    sha256 = "d115179d8ea852944cfd166a641af80f622a675d4c553d677f2b7ab91bf02c32",
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
        "//patches/openssh:0001-libcrypto-rename.patch",
        "//patches/openssh:0002-no-define-mkstemp.patch",
    ],
)

envoy_http_archive(
    name = "libvterm",
    build_file_content = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
    locations = dict(
        libvterm = dict(
            license = "MIT",
            license_url = "https://github.com/neovim/libvterm/blob/mirror/LICENSE",
            project_name = "libvterm",
            sha256 = "98c662f5af76c20710e26ca4677952f750a3472984cdaa5816a2b66909ba4082",
            strip_prefix = "libvterm-mirror",
            urls = ["https://github.com/neovim/libvterm/archive/mirror.zip"],
            version = "mirror",
        ),
    ),
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//patches/libvterm:0001-makefile.patch",
    ],
)

envoy_http_archive(
    name = "magic_enum",
    build_file_content = """cc_library(name = "magic_enum", hdrs = glob(["include/magic_enum/*.hpp"]), includes = ["include"], visibility = ["//visibility:public"])""",
    locations = dict(
        magic_enum = dict(
            license = "MIT",
            license_url = "https://github.com/Neargye/magic_enum/blob/master/LICENSE",
            project_name = "magic_enum",
            sha256 = "4fd719717102b308527528fa26ea93ce3c9d583aae8ffaf68e1199906ce22382",
            strip_prefix = "magic_enum-" + magic_enum_version,
            urls = ["https://github.com/Neargye/magic_enum/archive/" + magic_enum_version + ".zip"],
            version = magic_enum_version,
        ),
    ),
)
