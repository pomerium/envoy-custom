FROM debian
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
	&& apt-get -y install build-essential curl autoconf libxml2 \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*
RUN curl -Lo /usr/local/bin/bazelisk https://github.com/bazelbuild/bazelisk/releases/download/v1.28.1/bazelisk-linux-amd64 && \
  chmod +x /usr/local/bin/bazelisk