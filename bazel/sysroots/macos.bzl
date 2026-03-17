load("@aspect_bazel_lib//lib:repo_utils.bzl", "repo_utils")

def _macos_sysroot_impl(rctx):
    rctx.file("BUILD", """
filegroup(
    name = "sysroot",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
""")

    rctx.download(
        url = "https://github.com/cerisier/pkgutil/releases/download/v1.2.0/pkgutil_%s" % repo_utils.platform(rctx),
        sha256 = "3bcf79dbec6b7858ca0c1b6db03952ac122501a74073bac186c8080fcfb391fd",
        output = "pkgutil",
        executable = True,
    )

    rctx.download(
        url = "https://swcdn.apple.com/content/downloads/60/22/089-71960-A_W8BL1RUJJ6/5zkyplomhk1cm7z6xja2ktgapnhhti6wwd/CLTools_macOSNMOS_SDK.pkg",
        sha256 = "466ae4667fde372ef4402fc583298bfd5fba18c96a19f628da570855538c7c67",
        # stripPrefix = "Payload/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk",
        output = "CLTools_macOSNMOS_SDK.pkg",
    )

    prefix = "Payload/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk"

    # https://github.com/cerisier/toolchains_llvm_bootstrapped/blob/bcd0650fb1c00feaf71567c0c916ab7ed1ad9794/extensions/osx.bzl
    frameworks = [
        "CoreFoundation",
        "Foundation",
        "Kernel",
        "OSLog",
        "Security",
        "SystemConfiguration",
    ]
    includes = [
        "usr/include/*",
        "usr/lib/libc.tbd",
        "usr/lib/libcharset*",
        "usr/lib/libdl*",
        "usr/lib/libiconv*",
        "usr/lib/libm.tbd",
        "usr/lib/libobjc*",
        "usr/lib/libresolv*",
        "usr/lib/libpthread.tbd",
        "usr/lib/libSystem*",
    ]
    for framework in frameworks:
        includes = includes + ["System/Library/Frameworks/%s.framework/*" % framework]
        includes = includes + ["System/Library/PrivateFrameworks/%s.framework/*" % framework]

    include_args = []
    for inc in includes:
        include_args = include_args + ["--include", "%s/%s" % (prefix, inc)]

    cmd = [
        "./pkgutil",
    ] + include_args + [
        "--strip-components",
        "6",
        "--expand-full",
        "CLTools_macOSNMOS_SDK.pkg",
        ".",
    ]

    result = rctx.execute(cmd)
    if result.return_code != 0:
        fail(result.stdout + result.stderr)

macos_sysroot = repository_rule(
    implementation = _macos_sysroot_impl,
)
