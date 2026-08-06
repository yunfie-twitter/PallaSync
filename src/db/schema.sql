CREATE TABLE IF NOT EXISTS sync_records (
    relay_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    collection_name TEXT NOT NULL,
    action TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    device_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signature TEXT NOT NULL,
    UNIQUE (chain_id, record_id)
);

CREATE TABLE IF NOT EXISTS device_records (
    chain_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    encrypted_device_name TEXT NOT NULL,
    device_public_key TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (chain_id, device_id)
);

CREATE TABLE IF NOT EXISTS chain_public_keys (
    chain_id TEXT PRIMARY KEY,
    device_public_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deleted_chains (
    chain_id TEXT PRIMARY KEY,
    deleted_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_sync_records_chain_record
    ON sync_records(chain_id, record_id);

CREATE INDEX IF NOT EXISTS ix_sync_records_chain_relay_seq
    ON sync_records(chain_id, relay_seq);
