CREATE TABLE IF NOT EXISTS chains (
    chain_id TEXT PRIMARY KEY,
    chain_salt TEXT NOT NULL,
    admin_public_key TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    creator_device_id TEXT NOT NULL,
    creator_public_key TEXT NOT NULL,
    deleted_at_ms INTEGER DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    chain_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_public_key TEXT NOT NULL,
    encrypted_device_name TEXT NOT NULL,
    device_name_nonce TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (chain_id, device_id),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

CREATE TABLE IF NOT EXISTS sync_records (
    chain_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    collection_name TEXT NOT NULL,
    action TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    payload_nonce TEXT NOT NULL,
    device_id TEXT NOT NULL,
    lamport INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    signature TEXT NOT NULL,
    server_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    UNIQUE (chain_id, record_id),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

CREATE TABLE IF NOT EXISTS replay_nonces (
    chain_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (chain_id, device_id, nonce),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

CREATE TABLE IF NOT EXISTS cursors (
    chain_id TEXT NOT NULL,
    cursor_id TEXT PRIMARY KEY,
    server_sequence INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

CREATE INDEX IF NOT EXISTS idx_records_chain_sequence ON sync_records(chain_id, server_sequence);
CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON replay_nonces(expires_at_ms);
