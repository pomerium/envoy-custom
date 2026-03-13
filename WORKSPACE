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

envoy_version = "be5f52a703ca8199d2142bdfa85e1f4b29032286"

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
        "//patches/envoy:0003-envoy-copts.patch",
        "//patches/envoy:0004-protoc-gen-validate.patch",
        "//patches/envoy:0005-suppress-duplicate-wip-warnings.patch",
        "//patches/envoy:0006-coverage-format.patch",
        "//patches/envoy:0007-user-space-io-handle.patch",
        "//patches/envoy:0008-fake-upstream.patch",
        "//patches/envoy:0009-fix-integration-test-server-exit.patch",
        "//patches/envoy:0010-fix-mock-connection-race.patch",
        "//patches/envoy:0011-symbolizer-env.patch",
        "//patches/envoy:0012-foreign-cc-toolchains.patch",
        "//patches/envoy:0013-no-stdlib-deps.patch",
        "//patches/envoy:0014-fix-zstd-cli-threading.patch",
        "//patches/envoy:tmp-transport-socket-options.patch",
        "//patches/envoy:0015-fix-luajit-cross-compilation.patch",
    ],
    sha256 = "46e132c211dedbf08b6d2f6d04077c34b6a85b3381b94df4fecbe42def019537",
    strip_prefix = "envoy-" + envoy_version,
    url = "https://github.com/envoyproxy/envoy/archive/" + envoy_version + ".zip",
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

rules_foreign_cc_dependencies()

load("//bazel:toolchains.bzl", "pomerium_envoy_toolchains")

pomerium_envoy_toolchains()

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

rules_oci_version = "2.2.7"

http_archive(
    name = "rules_oci",
    sha256 = "b8db7ab889d501db33313620b2c8040dbb07e95c26a0fefe06004b35baf80e08",
    strip_prefix = "rules_oci-" + rules_oci_version,
    url = "https://github.com/bazel-contrib/rules_oci/releases/download/v" + rules_oci_version + "/rules_oci-v" + rules_oci_version + ".tar.gz",
)

load("@rules_oci//oci:dependencies.bzl", "rules_oci_dependencies")

rules_oci_dependencies()

load("@rules_oci//oci:repositories.bzl", "oci_register_toolchains")

oci_register_toolchains(name = "oci")

load("//bazel/sysroots:load_sysroots.bzl", "load_sysroots")

load_sysroots()

load("//bazel/sysroots:minimal_sysroot.bzl", "minimal_sysroot")

minimal_sysroot(
    name = "minimal_sysroot_linux_amd64",
    image = "@minimal_sysroot_image_linux_amd64",
)

minimal_sysroot(
    name = "minimal_sysroot_linux_arm64",
    image = "@minimal_sysroot_image_linux_arm64",
)

load("//bazel/cxx_libs:load_cxx_libs.bzl", "load_cxx_libs")

load_cxx_libs()

load("//bazel/cxx_libs:cxx_libs.bzl", "cxx_libs")

cxx_libs(
    name = "cxx_libs_linux_amd64",
    image = "@cxx_libs_image_linux_amd64",
)

cxx_libs(
    name = "cxx_libs_linux_arm64",
    image = "@cxx_libs_image_linux_arm64",
)
