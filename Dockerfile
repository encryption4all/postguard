# syntax=docker/dockerfile:1

# ── Stage 1: install cargo-chef once ─────────────────────────────────────────
FROM rust:1.90.0-slim AS chef
RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: compute the dependency recipe ───────────────────────────────────
FROM chef AS planner
COPY pg-core ./pg-core
COPY pg-pkg  ./pg-pkg
COPY pg-cli  ./pg-cli
COPY pg-ffi  ./pg-ffi
COPY pg-wasm ./pg-wasm
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cook (compile) only the dependencies ────────────────────────────
# This layer is cached as long as Cargo.toml / Cargo.lock don't change.
FROM chef AS builder
ARG CARGO_PROFILE=release
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --profile ${CARGO_PROFILE} --bin pg-pkg --recipe-path recipe.json

# Copy sources and build the application binary
COPY pg-core ./pg-core
COPY pg-pkg  ./pg-pkg
COPY pg-cli  ./pg-cli
COPY pg-ffi  ./pg-ffi
COPY pg-wasm ./pg-wasm
COPY Cargo.toml Cargo.lock ./
RUN cargo build --profile ${CARGO_PROFILE} --bin pg-pkg

# ── Stage 4: minimal runtime image ───────────────────────────────────────────
# Use a Debian-based runtime that provides glibc so the builder's binary can run.
FROM debian:trixie-slim
ARG CARGO_PROFILE=release
RUN groupadd -r nonroot \
    && useradd -r -g nonroot nonroot
RUN apt-get update && apt-get --no-install-recommends install -y ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/${CARGO_PROFILE}/pg-pkg /usr/local/bin/pg-pkg
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN mkdir -p /app && chown nonroot:nonroot /app
WORKDIR /app
USER nonroot

EXPOSE 8087

ENTRYPOINT ["/entrypoint.sh"]
