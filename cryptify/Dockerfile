# syntax=docker/dockerfile:1

# ── Stage 1: install cargo-chef once ─────────────────────────────────────────
FROM rust:1.96.1-slim-trixie AS chef
RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: compute the dependency recipe ───────────────────────────────────
# Build context is the REPO ROOT, not cryptify/: as a workspace member this
# crate resolves against the root manifest and the root lockfile, and cargo
# refuses to read a member without its siblings' manifests present. Build it
# with `docker build -f cryptify/Dockerfile .` from the repo root.
FROM chef AS planner
COPY pg-core   ./pg-core
COPY pg-pkg    ./pg-pkg
COPY pg-cli    ./pg-cli
COPY pg-ffi    ./pg-ffi
COPY cryptify  ./cryptify
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cook (compile) only the dependencies ────────────────────────────
# This layer is cached as long as Cargo.toml / Cargo.lock don't change.
FROM chef AS builder
ARG CARGO_PROFILE=release
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --profile ${CARGO_PROFILE} --bin cryptify --recipe-path recipe.json

# Copy sources and build the application binary
COPY pg-core   ./pg-core
COPY pg-pkg    ./pg-pkg
COPY pg-cli    ./pg-cli
COPY pg-ffi    ./pg-ffi
COPY cryptify  ./cryptify
COPY Cargo.toml Cargo.lock ./
RUN cargo build --profile ${CARGO_PROFILE} --bin cryptify

# ── Stage 4: minimal runtime image ───────────────────────────────────────────
FROM debian:trixie-slim
ARG CARGO_PROFILE=release
ENV ROCKET_CONFIG=config.toml
RUN groupadd -r nonroot \
    && useradd -r -g nonroot nonroot \
    && apt-get update \
    && apt-get --no-install-recommends install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/${CARGO_PROFILE}/cryptify /usr/local/bin/cryptify
RUN mkdir -p /app && chown nonroot:nonroot /app
WORKDIR /app
USER nonroot
RUN mkdir -p /tmp/data

EXPOSE 8000

CMD ["/usr/local/bin/cryptify"]
