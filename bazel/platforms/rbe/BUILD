licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = "docker.io/joekralicky/envoy-build@sha256:ac48b92e6a5724fdd4a69f2cdf4b4e883fd5d28b57117ee0edbcab47ef5472c3"

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
