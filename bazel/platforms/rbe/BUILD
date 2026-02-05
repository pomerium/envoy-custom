licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:6f566ff5582e08f540034c10d2866bf83acde371ab8af9c87db218344a70da79"

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
