# syntax=docker/dockerfile:1

# ── Stage 1: install cargo-chef once ─────────────────────────────────────────
# 1.96.1 matches cryptify's Dockerfile, and >=1.94 is now a hard floor: sqlx
# 0.9 declares rust-version 1.94.0, and sqlx 0.9 is what the workspace needs
# for pg-pkg and cryptify to agree on one libsqlite3-sys.
FROM rust:1.96.1-slim-trixie AS chef
RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: compute the dependency recipe ───────────────────────────────────
FROM chef AS planner
COPY pg-core  ./pg-core
COPY pg-pkg   ./pg-pkg
COPY pg-cli   ./pg-cli
COPY pg-ffi   ./pg-ffi
COPY pg-wasm  ./pg-wasm
# A workspace member cargo cannot read is a hard error even for a build that
# never compiles it: `cargo chef prepare` loads every member's manifest.
COPY cryptify ./cryptify
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cook (compile) only the dependencies ────────────────────────────
# This layer is cached as long as Cargo.toml / Cargo.lock don't change.
FROM chef AS builder
ARG CARGO_PROFILE=release
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --profile ${CARGO_PROFILE} --bin pg-pkg --recipe-path recipe.json

# Copy sources and build the application binary
COPY pg-core  ./pg-core
COPY pg-pkg   ./pg-pkg
COPY pg-cli   ./pg-cli
COPY pg-ffi   ./pg-ffi
COPY pg-wasm  ./pg-wasm
# A workspace member cargo cannot read is a hard error even for a build that
# never compiles it: `cargo chef prepare` loads every member's manifest.
COPY cryptify ./cryptify
COPY Cargo.toml Cargo.lock ./
RUN cargo build --profile ${CARGO_PROFILE} --bin pg-pkg

# ── Stage 4: minimal runtime image ───────────────────────────────────────────
# Use a Debian-based runtime that provides glibc so the builder's binary can run.
# Named so `delivery.yml` can exempt this stage from the build cache with
# `no-cache-filters`. The Rust stages above are what the cache exists for and
# stay cached; this one is where package currency lives (see the upgrade below).
FROM debian:trixie-slim AS runtime
ARG CARGO_PROFILE=release
RUN groupadd -r nonroot \
    && useradd -r -g nonroot nonroot
# `upgrade` before `install`, and both are load-bearing (#394).
#
# The base image ships `libssl3t64` and `openssl-provider-legacy` already
# installed, and `apt-get install` does not upgrade a package that is already
# present and satisfying — so installing `libssl3` leaves those two at whatever
# version the base snapshot froze. That is how DSA-6465-1 (CVE-2026-63073,
# critical) rode into both published images: the fix was in `trixie-security`,
# which the base's own sources already enable, and nothing here ever asked for
# it. `upgrade`, not `dist-upgrade`: a runtime image should not be adding or
# removing packages to satisfy changed dependencies during a release build.
RUN apt-get update && apt-get upgrade -y \
    && apt-get --no-install-recommends install -y ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/${CARGO_PROFILE}/pg-pkg /usr/local/bin/pg-pkg
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN mkdir -p /app && chown nonroot:nonroot /app
WORKDIR /app
USER nonroot

EXPOSE 8087

ENTRYPOINT ["/entrypoint.sh"]
