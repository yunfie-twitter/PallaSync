# syntax=docker/dockerfile:1.7

FROM rust:bookworm AS builder

WORKDIR /app

COPY Cargo.* ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    if [ -f Cargo.lock ]; then \
        cargo build --locked --release; \
    else \
        cargo build --release; \
    fi && \
    cp /app/target/release/pallasync-server /tmp/pallasync-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install --yes --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system pallasync && \
    useradd --system --gid pallasync --home-dir /nonexistent --shell /usr/sbin/nologin pallasync && \
    install --directory --owner=pallasync --group=pallasync /data

COPY --from=builder /tmp/pallasync-server /usr/local/bin/pallasync-server

USER pallasync:pallasync
WORKDIR /data

ENV PORT=3000 \
    DATABASE_URL=sqlite:///data/pallasync.sqlite

EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error "http://127.0.0.1:${PORT}/pallasync/v2/health" || exit 1

ENTRYPOINT ["/usr/local/bin/pallasync-server"]
