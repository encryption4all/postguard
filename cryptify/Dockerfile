# syntax=docker/dockerfile:1

# ── Stage 1: install cargo-chef once ─────────────────────────────────────────
FROM rust:1.96.1-slim-trixie AS chef
RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ── Stage 2: compute the dependency recipe ───────────────────────────────────
FROM chef AS planner
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY build.rs   ./build.rs
COPY src        ./src
COPY templates  ./templates
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cook (compile) only the dependencies ────────────────────────────
# This layer is cached as long as Cargo.toml / Cargo.lock don't change.
FROM chef AS builder
ARG CARGO_PROFILE=release
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --profile ${CARGO_PROFILE} --recipe-path recipe.json

# Copy sources and build the application binary
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY build.rs   ./build.rs
COPY src        ./src
COPY templates  ./templates
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
