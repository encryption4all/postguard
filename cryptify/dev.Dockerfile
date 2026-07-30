FROM rust:latest AS chef

# Install cargo-chef for dependency caching
RUN cargo install cargo-chef cargo-watch

WORKDIR /app

FROM chef AS planner
# Copy source to create recipe
COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

ENV ROCKET_PROFILE=debug

# Install system dependencies
RUN apt-get update  \
    && apt-get --no-install-recommends install -y libssl-dev pkg-config  \
    && rm -rf /var/lib/apt/lists/*

# Build dependencies using recipe (this layer gets cached!)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json

# Copy lockfile and manifest
COPY Cargo.toml .
COPY Cargo.lock .

# Create data directory
RUN mkdir -p /tmp/data

# The actual source will be mounted as a volume
EXPOSE 8000

# Use cargo-watch to rebuild only app code when source changes
CMD ["cargo", "watch", "--poll", "-x", "run"]
