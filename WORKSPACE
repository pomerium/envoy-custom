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

envoy_version = "607aaa985080750ae29ac9f6e49a31a5445d28f4"

openssh_version = "V_10_0_P2"

magic_enum_version = "a413fcc9c46a020a746907136a384c227f3cd095"

local_repository(
    name = "envoy_build_config",
    path = "bazel/envoy_build_config",
)

http_archive(
    name = "envoy",
    patch_args = [
        "-p1",
    ],
    patch_tool = "patch",
    patches = [
        "//patches/envoy:0001-revert-deps-drop-BoringSSL-linkstatic-patch-38621.patch",
        "//patches/envoy:0002-bump-dependencies.patch",
        "//patches/envoy:0003-envoy-copts.patch",
        "//patches/envoy:0004-pgv.patch",
        "//patches/envoy:0005-suppress-duplicate-wip-warnings.patch",
        "//patches/envoy:0006-coverage-format.patch",
        "//patches/envoy:0007-userspace-socket-40748.patch",
        "//patches/envoy:0008-downstream-connected-40747.patch",
        "//patches/envoy:tmp-fix-upstream-connection-callbacks.patch",
        "//patches/envoy:tmp-transport-socket-options.patch",
    ],
    sha256 = "5e4730e46a178ba1aefc133cac2ad1efe7423202e87c9db0758d18e740ff1ab2",
    strip_prefix = "envoy-" + envoy_version,
    url = "https://github.com/envoyproxy/envoy/archive/" + envoy_version + ".zip",
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repo.bzl", "envoy_repo")

envoy_repo()

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
    build_file_content = """
filegroup(
    name = "all",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
filegroup(
    name = "testdata_sshkey",
    srcs = glob(["regress/unittests/sshkey/testdata/*"]),
    visibility = ["//visibility:public"],
    testonly = True,
)
    """,
    locations = dict(
        openssh_portable = dict(
            license = "BSD",
            license_url = "https://github.com/openssh/openssh-portable/blob/master/LICENCE",
            project_name = "openssh-portable",
            sha256 = "885b67c6dddb116037f6ed45f4bf83b45fd235f334df73eb878d1e0b8b8c613b",
            strip_prefix = "openssh-portable-" + openssh_version,
            urls = ["https://github.com/openssh/openssh-portable/archive/" + openssh_version + ".zip"],
            version = "master",
        ),
    ),
    patch_args = [
        "-p1",
    ],
    patches = [
        # Openssh by default links against libcrypto with -lcrypto, but envoy's boringcrypto lib
        # is named crypto_internal
        "//patches/openssh:0001-libcrypto-rename.patch",
        # Removes the mkstemp #define that openssh adds for portability reasons, but is not needed
        # here and interferes with some envoy syscall mock code
        "//patches/openssh:0002-no-define-mkstemp.patch",
        # Links in the no-op security key implementation used in some openssh tests. We use libssh
        # standalone, but disable the security key feature, so the symbols are left undefined.
        "//patches/openssh:0003-ssh-sk-null.patch",
        # Avoid a memory leak in a test program in the configure script that would otherwise
        # disable P-521 elliptic key support in asan builds.
        "//patches/openssh:0004-configure-asan.patch",
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
