# FlossWing sandbox base — C++ toolchain.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder — update via `docker pull debian:12-slim` on first build.

FROM debian:12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        g++ \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN { \
        echo "language: cpp"; \
        echo "base: debian:12-slim"; \
        g++ --version | head -1; \
        ld --version | head -1; \
        dpkg-query -W -f='${Package}=${Version}\n' build-essential g++ libstdc++-12-dev; \
    } > /sbom.txt

WORKDIR /scratch/work
