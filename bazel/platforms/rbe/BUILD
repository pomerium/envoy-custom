package(default_visibility = ["//visibility:public"])

# Note: these platforms are for cross-compiling only. The envoy-build container image is only
# available for linux/amd64.

container_image = "ghcr.io/pomerium/envoy-build:22.1.1-1@sha256:67051c647045567b0c7069227b13e00490dd01bccf8d66288e7daa90cf8c0337"

platform(
    name = "linux_x64",
    exec_properties = {
        "container-image": "docker://" + container_image,
        "OSFamily": "linux",
    },
    parents = ["@envoy//bazel/platforms:linux_x64"],
)

platform(
    name = "linux_arm64",
    exec_properties = {
        "container-image": "docker://" + container_image,
        "OSFamily": "linux",
    },
    parents = ["@envoy//bazel/platforms:linux_arm64"],
)

platform(
    name = "macos",
    exec_properties = {
        "container-image": "docker://" + container_image,
        "OSFamily": "linux",
    },
    parents = ["@envoy//bazel/platforms:macos_arm64"],
)
