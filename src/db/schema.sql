-- §9 isolation: v2 tables are preserved, never converted or dropped.
CREATE TABLE IF NOT EXISTS v3_chains (chain_id TEXT PRIMARY KEY, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v3_objects (
 chain_id TEXT NOT NULL, kind TEXT NOT NULL, object_id TEXT NOT NULL,
 object_hash TEXT NOT NULL, body TEXT, log_id TEXT, relay_seq INTEGER,
 PRIMARY KEY(chain_id,kind,object_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS v3_record_ids ON v3_objects(chain_id,object_id) WHERE kind IN ('record','snapshot_part');
CREATE TABLE IF NOT EXISTS v3_registry (
 chain_id TEXT NOT NULL, device_id TEXT NOT NULL, generation INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','pending_keys','revoked')),
 enrolled_seq INTEGER NOT NULL, revoked_seq INTEGER,
 PRIMARY KEY(chain_id,device_id)
);
CREATE TABLE IF NOT EXISTS v3_log (
 chain_id TEXT NOT NULL, log_id TEXT NOT NULL, seq INTEGER NOT NULL,
 entry TEXT, head_hash TEXT NOT NULL, PRIMARY KEY(chain_id,log_id,seq)
);
CREATE TABLE IF NOT EXISTS v3_receipts (
 chain_id TEXT NOT NULL, kind TEXT NOT NULL, object_id TEXT NOT NULL,
 log_id TEXT NOT NULL, seq INTEGER, receipt TEXT NOT NULL,
 PRIMARY KEY(chain_id,kind,object_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS v3_receipt_seq ON v3_receipts(chain_id,log_id,seq) WHERE seq IS NOT NULL;
CREATE TABLE IF NOT EXISTS v3_transparency (
 chain_id TEXT NOT NULL, transparency_id TEXT NOT NULL, idx INTEGER NOT NULL,
 entry TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(chain_id,transparency_id,idx)
);
CREATE TABLE IF NOT EXISTS v3_heads (
 chain_id TEXT NOT NULL, transparency_id TEXT NOT NULL, idx INTEGER NOT NULL,
 head TEXT NOT NULL, PRIMARY KEY(chain_id,transparency_id,idx)
);
-- No FK: genesis, staged and deleted chain tokens still consume nonces.
CREATE TABLE IF NOT EXISTS v3_nonces (
 chain_id TEXT NOT NULL, signer_kind TEXT NOT NULL, device_id TEXT NOT NULL,
 nonce TEXT NOT NULL, expires_at_ms INTEGER NOT NULL,
 PRIMARY KEY(chain_id,signer_kind,device_id,nonce)
);
CREATE TABLE IF NOT EXISTS v3_outcomes (
 chain_id TEXT NOT NULL, scope TEXT NOT NULL, operation_id TEXT NOT NULL,
 digest TEXT NOT NULL, response TEXT NOT NULL,
 PRIMARY KEY(chain_id,scope,operation_id)
);
CREATE TABLE IF NOT EXISTS v3_offers (
 chain_id TEXT NOT NULL, request_id TEXT NOT NULL, offer TEXT NOT NULL,
 request TEXT, status TEXT NOT NULL, updated_seq INTEGER NOT NULL,
 PRIMARY KEY(chain_id,request_id)
);
CREATE TABLE IF NOT EXISTS v3_cursors (
 cursor TEXT PRIMARY KEY, chain_id TEXT NOT NULL, binding TEXT NOT NULL,
 state TEXT NOT NULL, expires_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS v3_rates (scope TEXT NOT NULL, identity TEXT NOT NULL, tokens REAL NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(scope,identity));
CREATE TABLE IF NOT EXISTS v3_deletions (chain_id TEXT PRIMARY KEY, deleting_device_id TEXT, admin_public_key TEXT NOT NULL, device_public_key TEXT, proof TEXT NOT NULL, outcome TEXT NOT NULL, request_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v3_imports (chain_id TEXT PRIMARY KEY, log_id TEXT NOT NULL, parameters TEXT NOT NULL, epoch TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v3_payload_nonces (chain_id TEXT NOT NULL, epoch INTEGER NOT NULL, nonce TEXT NOT NULL, record_id TEXT NOT NULL, PRIMARY KEY(chain_id,epoch,nonce));
CREATE TABLE IF NOT EXISTS v3_handoffs (chain_id TEXT NOT NULL,epoch INTEGER NOT NULL,compaction_id TEXT NOT NULL,due_at_ms INTEGER NOT NULL,expired INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(chain_id,epoch));
CREATE TABLE IF NOT EXISTS v3_delete_versions (chain_id TEXT NOT NULL,receipt_hash TEXT NOT NULL,proof TEXT NOT NULL,PRIMARY KEY(chain_id,receipt_hash));
CREATE TABLE IF NOT EXISTS v3_restart_barrier (id INTEGER PRIMARY KEY CHECK(id=1),barrier_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS v3_notices (chain_id TEXT PRIMARY KEY,notice TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v3_operator (id INTEGER PRIMARY KEY CHECK(id=1), origin TEXT NOT NULL, relay_key_id TEXT NOT NULL, revision INTEGER NOT NULL, disclosure_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v3_registry_history (id INTEGER PRIMARY KEY AUTOINCREMENT,chain_id TEXT NOT NULL,device_id TEXT NOT NULL,status TEXT NOT NULL,enrolled_seq INTEGER NOT NULL,revoked_seq INTEGER);
CREATE TRIGGER IF NOT EXISTS v3_registry_insert AFTER INSERT ON v3_registry BEGIN INSERT INTO v3_registry_history(chain_id,device_id,status,enrolled_seq,revoked_seq) VALUES(new.chain_id,new.device_id,new.status,new.enrolled_seq,new.revoked_seq); END;
CREATE TRIGGER IF NOT EXISTS v3_registry_update AFTER UPDATE ON v3_registry BEGIN INSERT INTO v3_registry_history(chain_id,device_id,status,enrolled_seq,revoked_seq) VALUES(new.chain_id,new.device_id,new.status,new.enrolled_seq,new.revoked_seq); END;
CREATE TABLE IF NOT EXISTS v3_offer_history (id INTEGER PRIMARY KEY AUTOINCREMENT,chain_id TEXT NOT NULL,request_id TEXT NOT NULL,offer TEXT NOT NULL,request TEXT,status TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS v3_offer_insert AFTER INSERT ON v3_offers BEGIN INSERT INTO v3_offer_history(chain_id,request_id,offer,request,status) VALUES(new.chain_id,new.request_id,new.offer,new.request,new.status); END;
CREATE TRIGGER IF NOT EXISTS v3_offer_update AFTER UPDATE ON v3_offers BEGIN INSERT INTO v3_offer_history(chain_id,request_id,offer,request,status) VALUES(new.chain_id,new.request_id,new.offer,new.request,new.status); END;
