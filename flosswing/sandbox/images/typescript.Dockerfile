# FlossWing sandbox base — Node.js 20 + TypeScript compiler.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder.

FROM node:20-bookworm-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Global tsc + tsx — pinned to a stable TS version. Image-build time only.
RUN npm install -g --no-audit --no-fund \
        typescript@5.4.5 \
        tsx@4.7.1 \
    && npm cache clean --force

RUN { \
        echo "language: typescript"; \
        echo "base: node:20-bookworm-slim"; \
        node --version; \
        npm --version; \
        tsc --version; \
        tsx --version; \
        npm ls --global --depth=0; \
    } > /sbom.txt

WORKDIR /scratch/work
