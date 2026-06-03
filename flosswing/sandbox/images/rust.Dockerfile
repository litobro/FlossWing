# FlossWing sandbox base — Rust toolchain.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder.

FROM rust:1.78-slim-bookworm@sha256:0fea967628dc796a2b9d1d57ddb3af3b3f0a35b6c8c0e23690dbe0ceb71a2dc9

# Rust image already includes cargo + rustc. Add coreutils for the entrypoint shell.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN { \
        echo "language: rust"; \
        echo "base: rust:1.78-slim-bookworm"; \
        rustc --version; \
        cargo --version --verbose; \
    } > /sbom.txt

WORKDIR /scratch/work
