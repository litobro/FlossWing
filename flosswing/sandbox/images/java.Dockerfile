# FlossWing sandbox base — Eclipse Temurin JDK 21.
#
# Per docs/specs/2026-06-02-v0.4-sandbox-design.md § Design decisions #1/#4.
# Sha256 below is a placeholder.

FROM eclipse-temurin:21-jdk-jammy@sha256:0000000000000000000000000000000000000000000000000000000000000000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN { \
        echo "language: java"; \
        echo "base: eclipse-temurin:21-jdk-jammy"; \
        java -version 2>&1; \
        javac -version 2>&1; \
    } > /sbom.txt

WORKDIR /scratch/work
