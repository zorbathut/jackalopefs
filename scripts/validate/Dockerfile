# Deep-mode image: everything scripts/validate needs, run as root with /dev/fuse (see container.sh and docs/validation.md). The base is pinned by digest; the package set is whatever the Arch repositories hold at build time and is recorded in /opt/tools/versions.txt.
FROM docker.io/library/archlinux:base@sha256:818793c894d94534c22f2149154a39ebaee57e4e67321023b0866a1d5722036c
RUN pacman -Syu --noconfirm --needed base-devel perl fuse3 fio xfsprogs acl attr libaio liburing gdbm libcap && pacman -Scc --noconfirm
# Root does not need user_allow_other, but a fusermount3 fallback or a future unprivileged run inside the image would.
RUN echo user_allow_other >> /etc/fuse.conf
ENV PATH=/usr/bin/core_perl:$PATH
COPY tools.sh /opt/tools.sh
RUN /opt/tools.sh /opt/tools
