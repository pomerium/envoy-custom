licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:eae2ca9973aaa641f01663573834cdad6910e7544c7970d07c0bf7dd628626f9"

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
