load("@bazel_skylib//rules:copy_file.bzl", "copy_file")
load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@rules_cc//cc:defs.bzl", "cc_library")

filegroup(
    name = "testdata_sshkey",
    testonly = True,
    srcs = glob(["regress/unittests/sshkey/testdata/*"]),
    visibility = ["//visibility:public"],
)

write_file(
    "compat_nlist_h",
    out = "nlist.h",
    content = [],
)

write_file(
    "compat_util_h",
    out = "util.h",
    content = [],
)

write_file(
    "endian_h",
    out = "endian.h",
    content = ["#include <machine/endian.h>"],
)

config_setting(
    name = "darwin",
    constraint_values = ["@platforms//os:macos"],
)

copy_file(
    name = "config_h",
    src = select({
        ":darwin": "@//bazel/foreign_cc/openssh/include/config_darwin:config.h",
        "//conditions:default": "@//bazel/foreign_cc/openssh/include/config_linux:config.h",
    }),
    out = "config.h",
)

cc_library(
    name = "libssh",
    srcs = [
        "addr.c",
        "addrmatch.c",
        "atomicio.c",
        "authfile.c",
        "bitmap.c",
        "chacha.c",
        "cipher.c",
        "cipher-aes.c",
        "cipher-aesctr.c",
        "cipher-chachapoly.c",
        "cipher-chachapoly-libcrypto.c",
        "cleanup.c",
        "compat.c",
        "digest-libc.c",
        "digest-openssl.c",
        "ed25519.c",
        "entropy.c",
        "fatal.c",
        "hash.c",
        "hmac.c",
        "krl.c",
        "log.c",
        "mac.c",
        "match.c",
        "misc.c",
        "platform-misc.c",
        "poly1305.c",
        "rijndael.c",
        "smult_curve25519_ref.c",
        "sntrup761.c",
        "ssh-ecdsa.c",
        "ssh-ecdsa-sk.c",
        "ssh-ed25519.c",
        "ssh-ed25519-sk.c",
        "ssh-pkcs11.c",
        "ssh-rsa.c",
        "ssh-sk-null.c",
        "sshbuf.c",
        "sshbuf-getput-basic.c",
        "sshbuf-getput-crypto.c",
        "sshbuf-io.c",
        "sshbuf-misc.c",
        "ssherr.c",
        "sshkey.c",
        "umac.c",
        "umac128.c",
        "utf8.c",
        "xmalloc.c",
    ] + [
        ":compat_nlist_h",
        ":compat_util_h",
        ":config_h",
    ] + glob(
        ["openbsd-compat/*.c"],
        exclude = [
            "openbsd-compat/readpassphrase.c",
            "openbsd-compat/setproctitle.c",
        ],
    ),
    hdrs = glob([
        "*.h",
        "openbsd-compat/*.h",
    ] + [
        "umac.c",
    ]) + select({
        ":darwin": [":endian_h"],
        "//conditions:default": [],
    }),
    copts = [
        "-Wno-pointer-sign",
        "-Wno-unused-parameter",
        "-Wno-unused-result",
        "-ftrapv",
        "-fzero-call-used-regs=used",
    ],
    defines = [
        "D_XOPEN_SOURCE=600",
        "D_BSD_SOURCE",
        "D_DEFAULT_SOURCE",
        "D_GNU_SOURCE",
        "WITH_OPENSSL=1",
    ],
    include_prefix = "openssh",
    includes = [
        ".",
    ],
    linkopts = ["-lcrypt"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//bazel:crypto",
        "@envoy//bazel:ssl",
    ],
    alwayslink = True,
)
