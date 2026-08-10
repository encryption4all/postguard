FROM rust:latest AS chef

# Install system dependencies
RUN apt-get update  \
    && apt-get --no-install-recommends install -y libssl-dev pkg-config  \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-chef for dependency caching
RUN cargo install cargo-chef cargo-watch

WORKDIR /app

FROM chef AS planner
# Build context is the REPO ROOT, not cryptify/, exactly as cryptify/Dockerfile
# does: since #277 this crate is a workspace member, so it resolves against the
# root manifest and the root lockfile, and there is no cryptify/Cargo.lock for a
# crate-local build to copy. Build it with
# `docker build -f cryptify/dev.Dockerfile .` from the repo root.
#
# Every member the root Cargo.toml lists has to be copied, even though this
# image only ever runs cryptify: `cargo chef prepare` shells out to
# `cargo metadata`, which loads every member's manifest before any target
# selection, so a member it cannot read is a hard error (#322):
#
#     error: failed to load manifest for workspace member `/app/pg-cli`
COPY pg-core   ./pg-core
COPY pg-pkg    ./pg-pkg
COPY pg-cli    ./pg-cli
COPY pg-ffi    ./pg-ffi
COPY cryptify  ./cryptify
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

ENV ROCKET_PROFILE=debug

# Build dependencies using recipe (this layer gets cached!)
# --bin cryptify for the same reason as Dockerfile:31: the recipe covers every
# member, so an unscoped cook also compiles pg-pkg's tree into an image whose
# only command is `cargo run --bin cryptify`.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --bin cryptify --recipe-path recipe.json

# The sources again, for the same reason the planner stage needs them: each
# stage starts from its parent image's filesystem, so `cargo watch` here loads
# every member's manifest just as `cargo chef prepare` did. A consumer that
# edits code live bind-mounts over these copies, under /app/cryptify now rather
# than /app; without a mount the image still runs on its own.
COPY pg-core   ./pg-core
COPY pg-pkg    ./pg-pkg
COPY pg-cli    ./pg-cli
COPY pg-ffi    ./pg-ffi
COPY cryptify  ./cryptify
COPY Cargo.toml Cargo.lock ./

# Create data directory
RUN mkdir -p /tmp/data

EXPOSE 8000

# Use cargo-watch to rebuild only app code when source changes. --bin cryptify
# because the working directory is the workspace root now, which holds more than
# one binary and cargo will not pick one for you.
CMD ["cargo", "watch", "--poll", "-x", "run --bin cryptify"]
