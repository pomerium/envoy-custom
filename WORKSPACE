workspace(name = "pomerium_envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Hedron's Compile Commands Extractor for Bazel
# https://github.com/hedronvision/bazel-compile-commands-extractor
http_archive(
    name = "hedron_compile_commands",
    sha256 = "e875b18876190b172ab59eaf193c2eec16fff8c46306c5eb0577ef7d1f8a65f7",
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

envoy_version = "f387231af8dd7274e37c5ae2cc797cb09a948818"

openssh_version = "V_10_3_P1"

magic_enum_version = "0.9.8"

readerwriterqueue_version = "1.0.7"

rules_oci_version = "2.3.1"

local_repository(
    name = "envoy_build_config",
    path = "bazel/envoy_build_config",
)

http_archive(
    name = "envoy",
    patch_args = ["-p1"],
    patch_tool = "patch",
    patches = [
        "//patches/envoy:0001-revert-deps-drop-BoringSSL-linkstatic-patch-38621.patch",
        "//patches/envoy:0002-envoy-copts.patch",
        "//patches/envoy:0003-add-external-patches.patch",
        "//patches/envoy:0004-suppress-duplicate-wip-warnings.patch",
        "//patches/envoy:0005-user-space-io-handle.patch",
        "//patches/envoy:0006-fake-upstream.patch",
        "//patches/envoy:0007-coverage-format.patch",
        "//patches/envoy:0008-sanitizer-deps.patch",
        "//patches/envoy:0009-luajit.patch",
        "//patches/envoy:0011-integration-tcp-client-write.patch",
        "//patches/envoy:0012-generic-proxy-trace-logs.patch",
        "//patches/envoy:0013-fuzz-toolchain-path.patch",
        "//patches/envoy:fix-antlr4-cpp-runtime.patch",
        "//patches/envoy:fix-integration-test-server-exit.patch",
        "//patches/envoy:fix-missing-symbolizer-env.patch",
        "//patches/envoy:fix-static-libgcc-flag.patch",
        "//patches/envoy:fix-tcmalloc-macos-constraints.patch",
        "//patches/envoy:fix-transport-socket-options.patch",
        "//patches/envoy:fix-allow-dev-shm.patch",  # exists in upstream main but not in 1.38.x
    ],
    sha256 = "af833ff8f9799499b44dee4276dad5fd5785638e73cb17ed38718565e49c7a5a",
    strip_prefix = "envoy-" + envoy_version,
    url = "https://github.com/envoyproxy/envoy/archive/" + envoy_version + ".tar.gz",
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy_api//bazel:envoy_http_archive.bzl", "envoy_http_archive")

# override aspect_bazel_lib; upstream envoy downloads the wrong tarball
envoy_http_archive(
    name = "aspect_bazel_lib",
    locations = {
        "aspect_bazel_lib": {
            "version": "2.21.2",
            "sha256": "53cadea9109e646a93ed4dc90c9bbcaa8073c7c3df745b92f6a5000daf7aa3da",
            "strip_prefix": "bazel-lib-2.21.2",
            "urls": ["https://github.com/aspect-build/bazel-lib/releases/download/v2.21.2/bazel-lib-v2.21.2.tar.gz"],
        },
    },
)

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies", "external_http_archive")

external_http_archive(
    name = "toolchains_llvm",
    patch_args = ["-p1"],
    patches = [
        # (temporary) upstream patch from https://github.com/envoyproxy/toolshed/blob/main/bazel/patches/toolchains_llvm.patch
        "@envoy_toolshed//:patches/toolchains_llvm.patch",
        # linux->darwin cross-compile support
        "//patches/toolchains_llvm:0002-darwin.patch",
    ],
)

external_http_archive(
    name = "luajit",
    build_file = "//bazel/foreign_cc:luajit.BUILD",
)

envoy_dependencies()

load("//bazel:repositories.bzl", "patch_antlr4_runtimes")

patch_antlr4_runtimes()

http_archive(
    name = "rules_oci",
    sha256 = "6d47e0bb9d3c269695cbb35abb603d1db08434376a1210867da8f6f4a9c630ba",
    strip_prefix = "rules_oci-" + rules_oci_version,
    url = "https://github.com/bazel-contrib/rules_oci/releases/download/v" + rules_oci_version + "/rules_oci-v" + rules_oci_version + ".tar.gz",
)

load("@rules_oci//oci:dependencies.bzl", "rules_oci_dependencies")

rules_oci_dependencies()

load("@rules_oci//oci:repositories.bzl", "oci_register_toolchains")

oci_register_toolchains(name = "oci")

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

load("//bazel:toolchains.bzl", "pomerium_envoy_toolchains")

pomerium_envoy_toolchains()

load("//bazel/sysroots:load_sysroots.bzl", "load_sysroots")

load_sysroots()

load("//bazel/cxx_libs:load_cxx_cross_libs.bzl", "load_cxx_cross_libs")

load_cxx_cross_libs()

load("//bazel/llvm_extras:load_llvm_extras.bzl", "load_llvm_extras")

load_llvm_extras()

load("@llvm_toolchain//:toolchains.bzl", "llvm_register_toolchains")

llvm_register_toolchains()

envoy_http_archive(
    name = "openssh_portable",
    build_file = "//bazel/foreign_cc:openssh.BUILD",
    locations = dict(
        openssh_portable = dict(
            license = "BSD",
            license_url = "https://github.com/openssh/openssh-portable/blob/master/LICENCE",
            project_name = "openssh-portable",
            sha256 = "c1a4420b1a25ba7336f62afd42ed5974d93455a2ab8c769b5e8e0c8ff8eedadc",
            strip_prefix = "openssh-portable-" + openssh_version,
            urls = ["https://github.com/openssh/openssh-portable/archive/" + openssh_version + ".tar.gz"],
            version = openssh_version,
        ),
    ),
    patch_args = ["-p1"],
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
            sha256 = "1e54959a3f3cb675938d858603ad69d0f3f7c82439fc2bf86d7232daec2bd10e",
            strip_prefix = "magic_enum-" + magic_enum_version,
            urls = ["https://github.com/Neargye/magic_enum/archive/v" + magic_enum_version + ".tar.gz"],
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
            sha256 = "532224ed052bcd5f4c6be0ed9bb2b8c88dfe7e26e3eb4dd9335303b059df6691",
            strip_prefix = "readerwriterqueue-" + readerwriterqueue_version,
            urls = ["https://github.com/cameron314/readerwriterqueue/archive/v" + readerwriterqueue_version + ".tar.gz"],
            version = readerwriterqueue_version,
        ),
    ),
)

http_archive(
    name = "argparse",
    sha256 = "9dcb3d8ce0a41b2a48ac8baa54b51a9f1b6a2c52dd374e28cc713bab0568ec98",
    strip_prefix = "argparse-3.2",
    url = "https://github.com/p-ranav/argparse/archive/refs/tags/v3.2.tar.gz",
)
