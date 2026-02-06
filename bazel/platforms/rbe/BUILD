licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:32d290c9781bdb86d78c26ae8352697cebc7096d46600eea957a56f6902c88cb"

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
