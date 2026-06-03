# FlossWing sandbox base — C toolchain.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions:
#   #1 — digest-pinned base, Debian-slim default
#   #4 — SBOM baked into the image at build time
#
# The sha256 digest below is a PLACEHOLDER. Update on first build:
#   docker pull debian:12-slim
#   docker images --digests debian:12-slim
# then paste the actual digest below.

FROM debian:12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# SBOM bake — captured once at build, read back per invocation via docker inspect.
RUN { \
        echo "language: c"; \
        echo "base: debian:12-slim"; \
        gcc --version | head -1; \
        ld --version | head -1; \
        dpkg-query -W -f='${Package}=${Version}\n' build-essential libc6 libc6-dev; \
    } > /sbom.txt

# Non-root user enforced by the runtime --user flag; this is documentation.
# Container runs as 65534:65534 (nobody:nogroup) per ARCH constraints.

# Default workdir; the runtime supplies the actual --workdir.
WORKDIR /scratch/work
