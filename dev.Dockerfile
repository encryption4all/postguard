FROM rust:latest AS chef
RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef cargo-watch
WORKDIR /app

FROM chef AS planner
# Every workspace member listed in the root Cargo.toml has to be copied, even
# when this image only builds pg-pkg: `cargo chef prepare` shells out to
# `cargo metadata`, which reads the manifest of every member and fails the whole
# build if one is absent. cryptify became a member in #277 and was missed, which
# broke this image (and postguard-e2e's stack, which builds it) with
# `failed to load manifest for workspace member /app/cryptify`.
# pg-wasm is in `exclude` rather than `members`, so it is not needed for that —
# it is copied because the image is also used to build it.
COPY pg-core ./pg-core
COPY pg-pkg ./pg-pkg
COPY pg-cli ./pg-cli
COPY pg-ffi ./pg-ffi
COPY pg-wasm ./pg-wasm
COPY cryptify ./cryptify
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json
RUN cargo run --bin pg-pkg -- gen

FROM chef AS dev
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json

# Copy generated keys to /keys, outside the bind-mounted /app directory
RUN mkdir /keys
COPY --from=planner /app/pkg_ibe.sec /keys/
COPY --from=planner /app/pkg_ibe.pub /keys/
COPY --from=planner /app/pkg_ibs.sec /keys/
COPY --from=planner /app/pkg_ibs.pub /keys/

EXPOSE 8087

# --poll so Claude Code file changes are picked up by cargo-watch
CMD ["/bin/sh", "-c", "cargo watch --poll -s 'cargo run --bin pg-pkg -- server ${IRMA_TOKEN:+-t $IRMA_TOKEN} -i $IRMA_SERVER --ibe-secret-path /keys/pkg_ibe.sec --ibe-public-path /keys/pkg_ibe.pub --ibs-secret-path /keys/pkg_ibs.sec --ibs-public-path /keys/pkg_ibs.pub'"]

