package(default_visibility = ["//visibility:public"])

# Note: these platforms are for cross-compiling only. The envoy-build container image is only
# available for linux/amd64.

container_image = "ghcr.io/pomerium/envoy-build:22.1.1-1@sha256:e58ed6feffccad36bd064efdb845eee9d7c7c73bf7b413a4089a9273d9db6b03"

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
