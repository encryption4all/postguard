FROM rust:1.90.0-slim AS builder
WORKDIR /app

COPY pg-core ./pg-core
COPY pg-pkg ./pg-pkg
COPY pg-cli ./pg-cli
COPY pg-wasm ./pg-wasm
COPY Cargo.toml Cargo.lock ./

RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*

RUN cargo build --release
RUN cp target/release/pg-pkg /usr/local/cargo/bin/pg-pkg

# Use a Debian-based runtime that provides glibc so the builder's binary can run, would've liked to use Alpine but glibc prevents that
FROM debian:trixie-slim
RUN groupadd -r nonroot \
    && useradd -r -g nonroot nonroot
RUN apt-get update && apt-get --no-install-recommends install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/pg-pkg /usr/local/bin/pg-pkg
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN mkdir -p /app /keys && chown nonroot:nonroot /app /keys
WORKDIR /app
USER nonroot

EXPOSE 8087

ENTRYPOINT ["/entrypoint.sh"]