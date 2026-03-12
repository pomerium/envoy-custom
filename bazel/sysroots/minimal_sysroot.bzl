def _minimal_sysroot_impl(rctx):
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
    name = "sysroot",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
""")

minimal_sysroot = repository_rule(
    implementation = _minimal_sysroot_impl,
    attrs = {
        "image": attr.label(
            mandatory = True,
        ),
    },
)
