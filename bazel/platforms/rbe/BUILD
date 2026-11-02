package(default_visibility = ["//visibility:public"])

# Note: these platforms are for cross-compiling only. The envoy-build container image is only
# available for linux/amd64.

container_image = "ghcr.io/pomerium/envoy-build:23.1.4-1@sha256:a9e6045a7322eb7be33575dfe6c343b61708e2d05486e2c98857f60dbb4f43e3"

platform(
    name = "linux_x64",
    exec_properties = {
        "container-image": container_image,
    },
    parents = ["@envoy//bazel/platforms:linux_x64"],
)

platform(
    name = "linux_arm64",
    exec_properties = {
        "container-image": container_image,
    },
    parents = ["@envoy//bazel/platforms:linux_arm64"],
)

platform(
    name = "macos",
    exec_properties = {
        "container-image": container_image,
    },
    parents = ["@envoy//bazel/platforms:macos_arm64"],
)
