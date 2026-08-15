FROM rust:latest AS chef
RUN apt-get update && apt-get --no-install-recommends install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef cargo-watch
WORKDIR /app

FROM chef AS planner
# A workspace member cargo cannot read is a hard error even for a build that
# never compiles it: `cargo chef prepare` loads every member's manifest.
# cryptify became a member in #277 and was missed here, which broke this image
# and, through it, postguard-e2e's stack.
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
# --bin pg-pkg for the same reason as Dockerfile:31: the recipe covers every
# member, so an unscoped cook builds cryptify's tree (rocket, lettre, rusqlite
# with `bundled`, i.e. the SQLite amalgamation) into an image whose only command
# is `cargo run --bin pg-pkg`. Scoping it drops 106 crates from the cook.
RUN cargo chef cook --bin pg-pkg --recipe-path recipe.json

# Copy generated keys to /keys, outside the bind-mounted /app directory
RUN mkdir /keys
COPY --from=planner /app/pkg_ibe.sec /keys/
COPY --from=planner /app/pkg_ibe.pub /keys/
COPY --from=planner /app/pkg_ibs.sec /keys/
COPY --from=planner /app/pkg_ibs.pub /keys/

EXPOSE 8087

# --poll so Claude Code file changes are picked up by cargo-watch
CMD ["/bin/sh", "-c", "cargo watch --poll -s 'cargo run --bin pg-pkg -- server ${IRMA_TOKEN:+-t $IRMA_TOKEN} -i $IRMA_SERVER --ibe-secret-path /keys/pkg_ibe.sec --ibe-public-path /keys/pkg_ibe.pub --ibs-secret-path /keys/pkg_ibs.sec --ibs-public-path /keys/pkg_ibs.pub'"]

