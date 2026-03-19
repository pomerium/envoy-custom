load("@bazel_skylib//rules:run_binary.bzl", "run_binary")
load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@pomerium_envoy//bazel/foreign_cc:luajit.bzl", "lj_cc_binary", "lj_cc_library", "luajit_copts")

lj_cc_library(
    name = "host_buildvm_lib",
    srcs = [
        "src/host/buildvm.c",
        "src/host/buildvm_asm.c",
        "src/host/buildvm_fold.c",
        "src/host/buildvm_lib.c",
        "src/host/buildvm_peobj.c",
    ],
    hdrs = glob([
        "dynasm/*.h",
        "src/*.h",
    ]) + [
        "src/host/buildvm.h",
        "src/host/buildvm_libbc.h",
        ":host_buildvm_arch_h",
        ":luajit_h",
    ],
    features = ["prefer_pic_for_opt_binaries"],
    host = True,
    includes = [
        "src/",
        "src/host/",
    ],
    linkstatic = True,
    alwayslink = True,
)

lj_cc_binary(
    name = "host_buildvm",
    host = True,
    deps = [":host_buildvm_lib"],
)

lj_cc_binary(
    name = "minilua",
    srcs = [
        "src/host/minilua.c",
    ],
    host = True,
    linkstatic = True,
)

write_file(
    "luajit_relver_h",
    out = "luajit_relver.h",
    # git timestamp of the current luajit version
    # todo: don't hard-code this
    content = ["1753364724"],
    # exec_compatible_with = HOST_CONSTRAINTS,
)

run_binary(
    name = "luajit_h",
    srcs = [
        "src/host/genversion.lua",
        "src/luajit_rolling.h",
        ":luajit_relver_h",
    ],
    outs = [
        "src/luajit.h",
    ],
    args = [
        "$(location src/host/genversion.lua)",
        "$(location src/luajit_rolling.h)",
        "$(location :luajit_relver_h)",
        "$(location src/luajit.h)",
    ],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":minilua",
)

alias(
    name = "dasm_dasc",
    actual = select({
        "@pomerium_envoy//bazel/foreign_cc:luajit_target_x64": "src/vm_x64.dasc",
        "@pomerium_envoy//bazel/foreign_cc:luajit_target_arm64": "src/vm_arm64.dasc",
    }),
)

# DASM = :minilua dynasm/dynasm.lua [...]

# add cflags:
# -DLJ_ARCH_HASFPU=1 (all)
#  -DLJ_ABI_SOFTFP=0 (all)
run_binary(
    name = "host_buildvm_arch_h",
    srcs = [
        "src/lj_arch.h",
        "src/lua.h",
        "src/luaconf.h",
        ":dasm_dasc",
    ] + glob([
        "src/*.dasc",
        "dynasm/*.lua",
    ]),
    outs = ["src/host/buildvm_arch.h"],
    args = [
        "$(location dynasm/dynasm.lua)",
        "-D",
        "ENDIAN_LE",
        "-D",
        "P64",
        "-D",
        "JIT",
        "-D",
        "FFI",
        "-D",
        "FPU",
        "-D",
        "HFABI",
    ] + select({
        "@pomerium_envoy//bazel/foreign_cc:luajit_target_x64": [],
        "@pomerium_envoy//bazel/foreign_cc:luajit_target_arm64": [
            "-D",
            "DUALNUM",
        ],
    }) + [
        "-o",
        "$(location src/host/buildvm_arch.h)",
    ] + [
        "$(location :dasm_dasc)",
    ],
    tool = ":minilua",
    # exec_compatible_with = HOST_CONSTRAINTS,
    # toolchains = [":host_buildvm_toolchain_type"],
)

run_binary(
    name = "lj_vm_s",
    outs = ["src/lj_vm.S"],
    args = ["-m"] + select({
        "@platforms//os:linux": ["elfasm"],
        "@platforms//os:osx": ["machasm"],
    }) + [
        "-o",
        "$(location src/lj_vm.S)",
    ],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

# LJLIB_C
ljlib_c_srcs = [
    "src/lib_base.c",
    "src/lib_bit.c",
    "src/lib_buffer.c",
    "src/lib_debug.c",
    "src/lib_ffi.c",
    "src/lib_io.c",
    "src/lib_jit.c",
    "src/lib_math.c",
    "src/lib_os.c",
    "src/lib_package.c",
    "src/lib_string.c",
    "src/lib_table.c",
]

run_binary(
    name = "lj_bcdef_h",
    srcs = ljlib_c_srcs,
    outs = ["src/lj_bcdef.h"],
    args = [
        "-m",
        "bcdef",
        "-o",
        "$(location src/lj_bcdef.h)",
    ] + ["$(location %s)" % src for src in ljlib_c_srcs],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

run_binary(
    name = "lj_ffdef_h",
    srcs = ljlib_c_srcs,
    outs = ["src/lj_ffdef.h"],
    args = [
        "-m",
        "ffdef",
        "-o",
        "$(location src/lj_ffdef.h)",
    ] + ["$(location %s)" % src for src in ljlib_c_srcs],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

run_binary(
    name = "lj_libdef_h",
    srcs = ljlib_c_srcs,
    outs = ["src/lj_libdef.h"],
    args = [
        "-m",
        "libdef",
        "-o",
        "$(location src/lj_libdef.h)",
    ] + ["$(location %s)" % src for src in ljlib_c_srcs],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

run_binary(
    name = "lj_recdef_h",
    srcs = ljlib_c_srcs,
    outs = ["src/lj_recdef.h"],
    args = [
        "-m",
        "recdef",
        "-o",
        "$(location src/lj_recdef.h)",
    ] + ["$(location %s)" % src for src in ljlib_c_srcs],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

run_binary(
    name = "jit_vmdef_lua",
    srcs = ljlib_c_srcs,
    outs = ["jit/vmdef.lua"],
    args = [
        "-m",
        "vmdef",
        "-o",
        "$(location jit/vmdef.lua)",
    ] + ["$(location %s)" % src for src in ljlib_c_srcs],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

run_binary(
    name = "lj_folddef_h",
    srcs = ["src/lj_opt_fold.c"],
    outs = ["src/lj_folddef.h"],
    args = [
        "-m",
        "folddef",
        "-o",
        "$(location src/lj_folddef.h)",
        "$(location src/lj_opt_fold.c)",
    ],
    # exec_compatible_with = HOST_CONSTRAINTS,
    tool = ":host_buildvm",
)

lj_cc_library(
    name = "ljvm",
    srcs = [":lj_vm_s"],
    host = False,
    linkstatic = True,
    alwayslink = True,
)

lj_cc_library(
    name = "luajit",
    srcs = [
        "src/lib_aux.c",
        "src/lib_init.c",
        "src/lj_alloc.c",
        "src/lj_api.c",
        "src/lj_asm.c",
        "src/lj_assert.c",
        "src/lj_bc.c",
        "src/lj_bcread.c",
        "src/lj_bcwrite.c",
        "src/lj_buf.c",
        "src/lj_carith.c",
        "src/lj_ccall.c",
        "src/lj_ccallback.c",
        "src/lj_cconv.c",
        "src/lj_cdata.c",
        "src/lj_char.c",
        "src/lj_clib.c",
        "src/lj_cparse.c",
        "src/lj_crecord.c",
        "src/lj_ctype.c",
        "src/lj_debug.c",
        "src/lj_dispatch.c",
        "src/lj_err.c",
        "src/lj_ffrecord.c",
        "src/lj_func.c",
        "src/lj_gc.c",
        "src/lj_gdbjit.c",
        "src/lj_ir.c",
        "src/lj_lex.c",
        "src/lj_lib.c",
        "src/lj_load.c",
        "src/lj_mcode.c",
        "src/lj_meta.c",
        "src/lj_obj.c",
        "src/lj_opt_dce.c",
        "src/lj_opt_fold.c",
        "src/lj_opt_loop.c",
        "src/lj_opt_mem.c",
        "src/lj_opt_narrow.c",
        "src/lj_opt_sink.c",
        "src/lj_opt_split.c",
        "src/lj_parse.c",
        "src/lj_prng.c",
        "src/lj_profile.c",
        "src/lj_record.c",
        "src/lj_serialize.c",
        "src/lj_snap.c",
        "src/lj_state.c",
        "src/lj_str.c",
        "src/lj_strfmt.c",
        "src/lj_strfmt_num.c",
        "src/lj_strscan.c",
        "src/lj_tab.c",
        "src/lj_trace.c",
        "src/lj_udata.c",
        "src/lj_vmevent.c",
        "src/lj_vmmath.c",
    ] + ljlib_c_srcs + [":ljvm"],
    hdrs = [
        ":lj_bcdef_h",
        ":lj_ffdef_h",
        ":lj_folddef_h",
        ":lj_libdef_h",
        ":lj_recdef_h",
        ":luajit_h",
    ] + glob(["src/*.h"]),
    host = False,
    includes = ["src/"],
    linkstatic = True,
    visibility = ["//visibility:public"],
)

lj_cc_binary(
    name = "luajit_bin",
    srcs = [
        "src/lauxlib.h",
        "src/lj_arch.h",
        "src/lua.h",
        "src/luaconf.h",
        "src/luajit.c",
        "src/lualib.h",
        ":ljvm",
        ":luajit",
        ":luajit_h",
    ],
    copts = luajit_copts(),
    host = False,
    includes = ["src/"],
    linkstatic = True,
)
