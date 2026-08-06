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

## Configuration

- `DATABASE_URL`: SQLx SQLite URL (default: `sqlite:pallasync.sqlite`)
- `PORT`: HTTP listen port (default: `3000`)
- `URL`: allowed CORS origin (default: `*`)

The resolved SQLite path is logged at startup. PallaSync v2 health is available at
`GET /pallasync/v2/health`. Relay-cursor clients should fetch records with
`?after_seq=0&limit=200` and persist the `PallaSync-Next-Seq` response header;
`PallaSync-Has-More` indicates whether another page is immediately available.
