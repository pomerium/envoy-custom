licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:2ef6ed40e1284335173f45ef0e530b29aa2685662f792e130bccb612e4f24c29"

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
