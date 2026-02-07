licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:e3291fc4975cc21d2087335bd2bafbc111f6eb52994470d5867bc78d16c86038"

platform(
    name = "linux_x64",
    exec_properties = {
        "container-image": "docker://" + container_image,
    },
    parents = ["@envoy//bazel/platforms/rbe:linux_x64"],
)

platform(
    name = "linux_arm64",
    exec_properties = {
        "container-image": "docker://" + container_image,
    },
    parents = ["@envoy//bazel/platforms/rbe:linux_arm64"],
)
