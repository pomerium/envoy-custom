FROM debian:trixie AS build

ARG LLVM_VERSION


RUN apt update \
 && apt -y install wget xz-utils \
 && mkdir /sysroot \
 && mkdir /sysroot/include \
 && mkdir /sysroot/lib \
 && if [ "$(uname -m)" = "x86_64" ]; then export TARGET="Linux-X64"; else export TARGET="Linux-ARM64"; fi \
 && if [ "$(uname -m)" = "x86_64" ]; then export TRIPLE="x86_64-unknown-linux-gnu"; else export TRIPLE="aarch64-unknown-linux-gnu"; fi \
 && wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-${TARGET}.tar.xz \
 && unxz -T0 ./LLVM-${LLVM_VERSION}-${TARGET}.tar.xz \
 && tar -xf ./LLVM-${LLVM_VERSION}-${TARGET}.tar

RUN if [ "$(uname -m)" = "x86_64" ]; then export TARGET="Linux-X64"; else export TARGET="Linux-ARM64"; fi \
 && if [ "$(uname -m)" = "x86_64" ]; then export TRIPLE="x86_64-unknown-linux-gnu"; else export TRIPLE="aarch64-unknown-linux-gnu"; fi \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/include/${TRIPLE}/c++/v1/__config_site /sysroot/include \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/lib/${TRIPLE}/libc++.a /sysroot/lib \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/lib/${TRIPLE}/libc++abi.a /sysroot/lib \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/lib/${TRIPLE}/libunwind.a /sysroot/lib \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/lib/clang/$(echo ${LLVM_VERSION} | cut -d'.' -f 1)/lib/${TRIPLE}/libclang_rt.builtins.a /sysroot/lib \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/lib/clang/$(echo ${LLVM_VERSION} | cut -d'.' -f 1)/lib/${TRIPLE}/clang_rt.crtbegin.o /sysroot/lib \
 && cp LLVM-${LLVM_VERSION}-${TARGET}/lib/clang/$(echo ${LLVM_VERSION} | cut -d'.' -f 1)/lib/${TRIPLE}/clang_rt.crtend.o /sysroot/lib

FROM scratch

COPY --from=build /sysroot /