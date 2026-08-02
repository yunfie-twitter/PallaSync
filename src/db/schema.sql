CREATE TABLE IF NOT EXISTS chains (
    chain_id TEXT PRIMARY KEY,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS control_events (
    chain_id TEXT NOT NULL,
    control_seq INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    PRIMARY KEY (chain_id, control_seq),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);

CREATE TABLE IF NOT EXISTS data_events (
    chain_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_seq INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    PRIMARY KEY (chain_id, device_id, device_seq),
    FOREIGN KEY (chain_id) REFERENCES chains(chain_id)
);
