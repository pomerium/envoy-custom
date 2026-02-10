workspace(name = "pomerium_envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Hedron's Compile Commands Extractor for Bazel
# https://github.com/hedronvision/bazel-compile-commands-extractor
http_archive(
    name = "hedron_compile_commands",
    strip_prefix = "bazel-compile-commands-extractor-9f69112e3f61b9df76a8275085dabad36ef37c96",
    url = "https://github.com/kralicky/bazel-compile-commands-extractor/archive/9f69112e3f61b9df76a8275085dabad36ef37c96.tar.gz",
)

load("@hedron_compile_commands//:workspace_setup.bzl", "hedron_compile_commands_setup")

hedron_compile_commands_setup()

load("@hedron_compile_commands//:workspace_setup_transitive.bzl", "hedron_compile_commands_setup_transitive")

hedron_compile_commands_setup_transitive()

load("@hedron_compile_commands//:workspace_setup_transitive_transitive.bzl", "hedron_compile_commands_setup_transitive_transitive")

hedron_compile_commands_setup_transitive_transitive()

load("@hedron_compile_commands//:workspace_setup_transitive_transitive_transitive.bzl", "hedron_compile_commands_setup_transitive_transitive_transitive")

hedron_compile_commands_setup_transitive_transitive_transitive()

envoy_version = "6d9bb7d9a85d616b220d1f8fe67b61f82bbdb8d3"

openssh_version = "V_10_2_P1"

magic_enum_version = "a413fcc9c46a020a746907136a384c227f3cd095"

readerwriterqueue_version = "1.0.7"

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
        "//patches/envoy:0004-protoc-gen-validate.patch",
        "//patches/envoy:0005-suppress-duplicate-wip-warnings.patch",
        "//patches/envoy:0006-coverage-format.patch",
        "//patches/envoy:0007-user-space-io-handle.patch",
        "//patches/envoy:0008-fake-upstream.patch",
        "//patches/envoy:0011-msan-symbolizer.patch",
        "//patches/envoy:0012-foreign-cc-toolchains.patch",
        "//patches/envoy:tmp-transport-socket-options.patch",
    ],
    sha256 = "bb111b2037e35d8732f12f003ccf82e0d09dfc8a8b7810e849eb081f36d50ddc",
    strip_prefix = "envoy-" + envoy_version,
    url = "https://github.com/envoyproxy/envoy/archive/" + envoy_version + ".zip",
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:bazel_deps.bzl", "envoy_bazel_dependencies")

envoy_bazel_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

load("@envoy//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies(
    register_built_pkgconfig_toolchain = False,
    register_built_tools = False,
)

load("//bazel:toolchains.bzl", "pomerium_envoy_toolchains")

pomerium_envoy_toolchains()

load("@llvm_toolchain//:toolchains.bzl", "llvm_register_toolchains")

llvm_register_toolchains()

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
            sha256 = "8eb83ec34ac4714ca3c545e593d5cfb7f383ee80cfcafd9a04424539390a6398",
            strip_prefix = "openssh-portable-" + openssh_version,
            urls = ["https://github.com/openssh/openssh-portable/archive/" + openssh_version + ".zip"],
            version = openssh_version,
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
        # This also links in ssh-pkcs11.o which provides the no-op implementations of some pkcs11
        # functions.
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

envoy_http_archive(
    name = "readerwriterqueue",
    build_file_content = """cc_library(name = "readerwriterqueue", hdrs = glob(["*.h"]), include_prefix="readerwriterqueue", visibility = ["//visibility:public"])""",
    locations = dict(
        readerwriterqueue = dict(
            license = "BSD",
            license_url = "https://github.com/cameron314/readerwriterqueue/blob/master/LICENSE.md",
            project_name = "readerwriterqueue",
            sha256 = "ab5535466d0379963e5944a85ad3cd08c033006ddff0380cbb79d5c2a80f43db",
            strip_prefix = "readerwriterqueue-" + readerwriterqueue_version,
            urls = ["https://github.com/cameron314/readerwriterqueue/archive/v" + readerwriterqueue_version + ".zip"],
            version = readerwriterqueue_version,
        ),
    ),
)
