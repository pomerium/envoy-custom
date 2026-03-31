genrule(
    name = "crane_bin",
    outs = ["crane"],
    cmd = "cp $(CRANE_BIN) $@",
    executable = True,
    toolchains = ["@oci_crane_toolchains//:current_toolchain"],
)

exports_files(["update_index.sh.tpl"])
