# FlossWing sandbox base — Node.js 20 (JavaScript).
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder.

FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN { \
        echo "language: javascript"; \
        echo "base: node:20-bookworm-slim"; \
        node --version; \
        npm --version; \
        npm ls --global --depth=0 2>/dev/null || true; \
    } > /sbom.txt

WORKDIR /scratch/work
