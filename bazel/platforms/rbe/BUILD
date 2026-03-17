package(default_visibility = ["//visibility:public"])

# Note: these platforms are for cross-compiling only. The envoy-build container image is only
# available for linux/amd64.

container_image = "ghcr.io/pomerium/envoy-build:22.1.1-1@sha256:77b3807b4109237d5a22d296f468352cc4680f0181c2038d055926872a85ecc4"

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
