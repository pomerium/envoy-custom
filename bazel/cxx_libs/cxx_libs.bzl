def _cxx_libs_impl(rctx):
    img_path = rctx.path(rctx.attr.image).dirname
    manifest = json.decode(rctx.read("%s/index.json" % img_path))["manifests"][0]["digest"].removeprefix("sha256:")
    layer = json.decode(rctx.read("%s/blobs/sha256/%s" % (img_path, manifest)))["layers"][0]["digest"].removeprefix("sha256:")

    layer_blob = "%s/blobs/sha256/%s" % (img_path, layer)
    rctx.symlink(layer_blob, "layer.tgz")
    rctx.extract(
        archive = "layer.tgz",
        output = ".",
    )
    rctx.delete("layer.tgz")
    rctx.file("BUILD", """
filegroup(
    name = "cxx_libs",
    srcs = [
        "include/__config_site",
        "//lib:libc++.a",
        "//lib:libc++abi.a",
        "//lib:libunwind.a",
        "//lib:clang_rt.crtbegin.o",
        "//lib:clang_rt.crtend.o",
    ],
    visibility = ["//visibility:public"],
)
""")
    rctx.file("lib/BUILD", 'exports_files(glob(["*"]))')

cxx_libs = repository_rule(
    implementation = _cxx_libs_impl,
    attrs = {
        "image": attr.label(
            mandatory = True,
        ),
    },
)

def _cxx_libs_darwin_impl(rctx):
    img_path = rctx.path(rctx.attr.image).dirname
    manifest = json.decode(rctx.read("%s/index.json" % img_path))["manifests"][0]["digest"].removeprefix("sha256:")
    layer = json.decode(rctx.read("%s/blobs/sha256/%s" % (img_path, manifest)))["layers"][0]["digest"].removeprefix("sha256:")

    layer_blob = "%s/blobs/sha256/%s" % (img_path, layer)
    rctx.symlink(layer_blob, "layer.tgz")
    rctx.extract(
        archive = "layer.tgz",
        output = ".",
    )
    rctx.delete("layer.tgz")
    rctx.file("BUILD", """
filegroup(
    name = "cxx_libs",
    srcs = [
        "include/__config_site",
        "//lib:libc++.a",
        "//lib:libc++abi.a",
        "//lib:libunwind.a",
        "//lib:libclang_rt.osx.a",
    ],
    visibility = ["//visibility:public"],
)
""")

    rctx.file("lib/BUILD", 'exports_files(glob(["*"]))')

cxx_libs_darwin = repository_rule(
    implementation = _cxx_libs_darwin_impl,
    attrs = {
        "image": attr.label(
            mandatory = True,
        ),
    },
)
