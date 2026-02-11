licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:c48d9837cb0ea59ef5a2fb02b4b693090fcbe79438a3ca11b3f5e2f94d2613b8"

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
