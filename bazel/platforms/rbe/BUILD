licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

container_image = {
    "linux_x64": "docker.io/joekralicky/envoy-build@sha256:6456bd9224bf6405eefabb1d60f61e31638481510d953ca0b4ccab255ce5d6d1",
    "linux_arm64": "docker.io/joekralicky/envoy-build@sha256:ab969b9e2605472fe84d7c0ac50068c50a605bffa52acc185838850e385976c0",
}

platform(
    name = "linux_x64",
    exec_properties = {
        "container-image": "docker://" + container_image["linux_x64"],
    },
    parents = ["@envoy//bazel/platforms/rbe:linux_x64"],
)

platform(
    name = "linux_arm64",
    exec_properties = {
        "container-image": "docker://" + container_image["linux_arm64"],
    },
    parents = ["@envoy//bazel/platforms/rbe:linux_arm64"],
)
