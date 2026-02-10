FROM debian:trixie AS base
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=tmpfs,target=/var/cache/apt \
    --mount=type=tmpfs,target=/var/lib/apt/lists \
    apt-get update \
 && apt-get install -y --no-install-recommends \
      libc6-dev \
			ca-certificates \
			patch \
			git \
			curl \
			make \
			cmake \
			ninja-build \
			meson \
			pkg-config \
			m4 \
			autoconf \
			automake \
			libxml2

RUN curl -Lo /usr/local/bin/bazelisk https://github.com/bazelbuild/bazelisk/releases/download/v1.28.1/bazelisk-linux-${TARGETARCH} \
 && chmod +x /usr/local/bin/bazelisk \
 && groupadd -g 1000 build \
 && useradd -m -u 1000 -g 1000 -s /bin/bash build

FROM base AS toolchain-setup

WORKDIR /workspace

COPY WORKSPACE BUILD envoy.bazelrc .bazelrc .bazelversion \
	 /workspace/
COPY api/ /workspace/api
COPY bazel/ /workspace/bazel
COPY patches/ /workspace/patches
COPY source/ /workspace/source
COPY test/ /workspace/test
COPY tools/ /workspace/tools

RUN /usr/local/bin/bazelisk build --nobuild //:envoy

RUN --mount=type=tmpfs,target=/var/cache/apt \
    --mount=type=tmpfs,target=/var/lib/apt/lists \
    apt-get update \
 && apt-get install -y --no-install-recommends \
	  rsync

COPY ci/BUILD /workspace/ci/BUILD

RUN mkdir -p /tmp/toolchain \
 && /usr/local/bin/bazelisk cquery --output=files //ci:llvm_toolchain_targets 2>/dev/null | rsync -a --files-from=- $(/usr/local/bin/bazelisk info output_base) /tmp/toolchain \
 && mv /tmp/toolchain/external/llvm_toolchain_llvm /toolchain \
 && rm -rf /tmp/toolchain

# work around a bug(?) in toolchains_llvm that adds these lib64 directories to modulemap files,
# but these directories don't exist here
RUN mkdir -p /toolchain/lib64/clang/$(/toolchain/bin/clang -dumpversion | cut -d'.' -f1)/include \
 && mkdir -p /toolchain/lib64/clang/$(/toolchain/bin/clang -dumpversion)/include

FROM base
COPY --from=toolchain-setup /toolchain /toolchain
ENV BAZEL_LLVM_PATH=/toolchain

USER 1000:1000
