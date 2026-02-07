FROM debian AS base
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
			autoconf \
			automake \
			libxml2 \
 && curl -Lo /usr/local/bin/bazelisk https://github.com/bazelbuild/bazelisk/releases/download/v1.28.1/bazelisk-linux-amd64 \
 && chmod +x /usr/local/bin/bazelisk \
 && groupadd -g 1000 build \
 && useradd -m -u 1000 -g 1000 -s /bin/bash build

USER 1000:1000
