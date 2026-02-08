FROM rust:1.93.0-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config libssl-dev libpam0g-dev openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release

FROM scratch
COPY --from=builder /app/target/release/libpam_rssh.so /
