# PallaSync Server

A high-performance relay server for the PallaSync Protocol, written in Rust.

## Architecture
- **Framework**: Axum (Tokio)
- **Database**: SQLite (SQLx)
- **Role**: Relay for E2E-encrypted Sync events and Control Logs.

## Setup
```bash
cargo build
cargo run
```

## Docker

Start the relay with a persistent named volume:

```bash
cp .env.example .env
docker compose up --detach --build
docker compose ps
```

The default endpoint is `http://localhost:3000`. Verify the container health with:

```bash
curl --fail http://localhost:3000/pallasync/v2/health
docker compose logs --follow pallasync
```

`PALLASYNC_HOST_PORT` changes the host-side port. `PALLASYNC_CORS_ORIGIN`
accepts `*` or one exact allowed origin. The SQLite database is stored in the
`pallasync-data` volume at `/data/pallasync.sqlite` and is retained by
`docker compose down`. Do not use `docker compose down --volumes` unless the
relay database should be permanently deleted.

For a direct Docker invocation:

```bash
docker build --tag pallasync-server:local .
docker run --detach --name pallasync \
  --publish 3000:3000 \
  --volume pallasync-data:/data \
  --env URL='*' \
  pallasync-server:local
```

## Configuration

- `DATABASE_URL`: SQLx SQLite URL (default: `sqlite:pallasync.sqlite`)
- `PORT`: HTTP listen port (default: `3000`)
- `URL`: allowed CORS origin (default: `*`)

The resolved SQLite path is logged at startup. PallaSync v2 health is available at
`GET /pallasync/v2/health`. Relay-cursor clients should fetch records with
`?after_seq=0&limit=200` and persist the `PallaSync-Next-Seq` response header;
`PallaSync-Has-More` indicates whether another page is immediately available.
