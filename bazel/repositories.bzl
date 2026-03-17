# This is a replacement for the antlr4-cpp-runtime workaround in upstream envoy, which seems to have
# inadvertently created an infinite symlink loop in external/.
# See patches/envoy/0016-remove-antlr4-cpp-runtime.patch for the original code.

def _patch_antlr4_runtimes_impl(rctx):
    rctx.file("BUILD", """
package(default_visibility = ["//visibility:public"])

# Alias to cel-cpp's embedded ANTLR4 runtime.
alias(
    name = "antlr4-cpp-runtime",
    actual = "@antlr4_runtimes//:cpp",
)
""")

patch_antlr4_runtimes_rule = repository_rule(
    implementation = _patch_antlr4_runtimes_impl,
)

def patch_antlr4_runtimes():
    patch_antlr4_runtimes_rule(name = "antlr4-cpp-runtime")
