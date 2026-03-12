FROM debian:trixie AS build

RUN apt update \
 && apt download libc-dev-bin libcrypt-dev linux-libc-dev rpcsvc-proto libc6-dev libc6 libxml2 \
 && mkdir /sysroot \
 && ls *.deb | xargs -I{} dpkg-deb -x {} /sysroot \
 && ln -rs /sysroot/usr/lib /sysroot/lib \
 && ln -rs /sysroot/usr/lib64 /sysroot/lib64 \
 && ln -rs /sysroot/usr/bin /sysroot/bin \
 && rm -rf /sysroot/usr/share

FROM scratch

COPY --from=build /sysroot /