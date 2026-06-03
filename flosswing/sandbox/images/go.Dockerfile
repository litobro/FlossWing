# FlossWing sandbox base — Go toolchain.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder.

FROM golang:1.22-bookworm@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Disable network during go build inside the container — sandbox already
# enforces --network=none, but make it the language default too so that
# accidental `go mod download` fails fast with a comprehensible error.
ENV GOFLAGS="-mod=vendor" \
    GOTOOLCHAIN="local"

RUN { \
        echo "language: go"; \
        echo "base: golang:1.22-bookworm"; \
        go version; \
        go env GOTOOLCHAIN GOFLAGS; \
    } > /sbom.txt

WORKDIR /scratch/work
