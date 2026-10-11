# syntax=docker/dockerfile:1.7

FROM rust:bookworm AS builder

WORKDIR /app
ARG PALLASYNC_BUILD_JOBS=2

COPY Cargo.* ./
COPY src ./src
COPY docs/privacy.schema.json ./docs/privacy.schema.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    if [ -f Cargo.lock ]; then \
        cargo build --locked --release --bins --jobs "$PALLASYNC_BUILD_JOBS"; \
    else \
        cargo build --release --bins --jobs "$PALLASYNC_BUILD_JOBS"; \
    fi && \
    cp /app/target/release/pallasync-server /tmp/pallasync-server && \
    cp /app/target/release/pallasync-operator /tmp/pallasync-operator

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install --yes --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 pallasync && \
    useradd --system --uid 10001 --gid pallasync --home-dir /nonexistent --shell /usr/sbin/nologin pallasync && \
    install --directory --owner=pallasync --group=pallasync /data

COPY --from=builder /tmp/pallasync-server /usr/local/bin/pallasync-server
COPY --from=builder /tmp/pallasync-operator /usr/local/bin/pallasync-operator
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/pallasync-entrypoint

USER pallasync:pallasync
WORKDIR /data

ENV PALLASYNC_BIND_ADDR=0.0.0.0:3000 \
    DATABASE_URL=sqlite:///data/pallasync.sqlite

EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error "http://127.0.0.1:3000/pallasync/v3/health" || exit 1

ENTRYPOINT ["/usr/local/bin/pallasync-entrypoint"]
