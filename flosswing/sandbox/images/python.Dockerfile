# FlossWing sandbox base — Python 3.11.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder.

FROM python:3.11-slim-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Pythonic defaults: unbuffered stdio, no bytecode written to read-only root.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN { \
        echo "language: python"; \
        echo "base: python:3.11-slim-bookworm"; \
        python --version; \
        pip --version; \
        pip freeze; \
    } > /sbom.txt

WORKDIR /scratch/work
