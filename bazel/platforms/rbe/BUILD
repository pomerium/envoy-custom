licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:634cb2d0f8405b6e77b5a0e91ebf9956850b75c7e8493f8eb169c92d5ae330ca"

platform(
    name = "linux_x64",
    exec_properties = {
        "container-image": "docker://" + container_image,
        "dockerNetwork": "bridge",
    },
    parents = ["@envoy//bazel/platforms/rbe:linux_x64"],
)

platform(
    name = "linux_arm64",
    exec_properties = {
        "container-image": "docker://" + container_image,
        "dockerNetwork": "bridge",
    },
    parents = ["@envoy//bazel/platforms/rbe:linux_arm64"],
)
