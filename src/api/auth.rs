use super::{
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::{
    config::RelayConfig,
    crypto::{jcs, verify::*},
};
use axum::http::{HeaderMap, Method, Uri};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};
#[derive(Clone)]
pub struct Auth {
    pub token: Value,
    pub device: Option<String>,
}
impl Auth {
    pub fn admin(&self) -> bool {
        self.device.is_none()
    }
    pub fn require_admin(&self) -> Result<()> {
        if !self.admin() {
            Err(err("ADMIN_REQUIRED"))
        } else {
            Ok(())
        }
    }
    pub fn owns(&self, id: &str) -> bool {
        self.admin() || self.device.as_deref() == Some(id)
    }
}
pub async fn rate(
    db: &mut SqliteConnection,
    cfg: &RelayConfig,
    scope: &str,
    identity: &str,
) -> Result<()> {
    let policy = &cfg.privacy["rate_limits"][scope];
    let burst = n(policy, "burst") as f64;
    let refill = n(policy, "requests_per_minute") as f64 / 60000.0;
    let t = now();
    let row = sqlx::query("SELECT tokens,updated_at_ms FROM v3_rates WHERE scope=? AND identity=?")
        .bind(scope)
        .bind(identity)
        .fetch_optional(&mut *db)
        .await?;
    let tokens = if let Some(row) = row {
        let old: f64 = row.get("tokens");
        let time: i64 = row.get("updated_at_ms");
        (old + (t.saturating_sub(time as u64)) as f64 * refill).min(burst)
    } else {
        burst
    };
    if tokens < 1.0 {
        return Err(err("RATE_LIMITED")
            .context(json!({"retry_after_ms":((1.0-tokens)/refill).ceil() as u64,"scope":scope})));
    }
    sqlx::query("INSERT INTO v3_rates(scope,identity,tokens,updated_at_ms) VALUES(?,?,?,?) ON CONFLICT(scope,identity) DO UPDATE SET tokens=excluded.tokens,updated_at_ms=excluded.updated_at_ms").bind(scope).bind(identity).bind(tokens-1.0).bind(t as i64).execute(db).await?;
    Ok(())
}
pub struct AuthRequest<'a> {
    pub headers: &'a HeaderMap,
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub body: &'a [u8],
    pub chain_id: &'a str,
    pub proposed_key: Option<&'a str>,
    pub route: &'a str,
}
pub async fn authenticate(
    db: &mut SqliteConnection,
    cfg: &RelayConfig,
    request: AuthRequest<'_>,
) -> Result<Auth> {
    let AuthRequest {
        headers,
        method,
        uri,
        body,
        chain_id,
        proposed_key,
        route,
    } = request;
    let h = headers
        .get("authorization")
        .ok_or_else(|| err("TOKEN_REQUIRED"))?
        .to_str()
        .map_err(|_| err("TOKEN_SIGNATURE_INVALID"))?;
    let raw = h
        .strip_prefix("PallaSync ")
        .ok_or_else(|| err("TOKEN_REQUIRED"))?;
    let bytes = decode(raw, None).map_err(|_| err("TOKEN_SIGNATURE_INVALID"))?;
    let token = jcs::parse(&bytes).map_err(|_| err("TOKEN_SIGNATURE_INVALID"))?;
    signed(
        &token,
        &[
            ("v", "int"),
            ("aud", "string"),
            ("chain_id", "b32"),
            ("signer_kind", "device|admin"),
            ("device_id", "uuid?"),
            ("method", "string"),
            ("path", "string"),
            ("query", "string"),
            ("body_sha256", "b32"),
            ("issued_at_ms", "int"),
            ("expires_at_ms", "int"),
            ("nonce", "b16"),
        ],
    )
    .map_err(|_| err("TOKEN_SIGNATURE_INVALID"))?;
    // The Authorization serialization itself is JCS, unlike whitespace-tolerant body objects.
    if bytes != jcs::canonicalize_json(&token).unwrap()
        || n(&token, "v") != 3
        || (s(&token, "signer_kind") == "admin") != token["device_id"].is_null()
    {
        return Err(err("TOKEN_SIGNATURE_INVALID"));
    }
    let q = canonical_query(uri.query().unwrap_or(""))?;
    if s(&token, "aud") != cfg.origin
        || s(&token, "chain_id") != chain_id
        || s(&token, "method") != method.as_str()
        || s(&token, "path") != uri.path()
        || s(&token, "query") != query_string(&q)
        || s(&token, "body_sha256") != hash_bytes(body)
    {
        return Err(err("TOKEN_BINDING_MISMATCH"));
    }
    let issued = n(&token, "issued_at_ms");
    let expires = n(&token, "expires_at_ms");
    let t = now();
    if issued >= expires {
        return Err(err("TOKEN_SIGNATURE_INVALID"));
    }
    if expires - issued > 300000 {
        return Err(err("TOKEN_TTL_TOO_LONG"));
    }
    if issued > t + 60000 {
        return Err(err("TOKEN_NOT_YET_VALID").context(json!({"retry_after_ms":issued-t-60000})));
    }
    if t > expires + 60000 {
        return Err(err("TOKEN_EXPIRED"));
    }
    let device = token["device_id"].as_str().map(str::to_owned);
    if proposed_key.is_some() && device.is_some() {
        return Err(err("ADMIN_REQUIRED"));
    }
    let c = store::load(&mut *db, chain_id).await?;
    let deletion=sqlx::query("SELECT admin_public_key,deleting_device_id,device_public_key FROM v3_deletions WHERE chain_id=?").bind(chain_id).fetch_optional(&mut *db).await?;
    let mut device_state = None;
    let key = if let Some(d) = &deletion {
        if let Some(id) = &device {
            if d.get::<Option<String>, _>("deleting_device_id").as_ref() != Some(id) {
                return Err(err("TOKEN_SIGNATURE_INVALID"));
            }
            d.get::<Option<String>, _>("device_public_key")
                .ok_or_else(|| err("DEVICE_UNKNOWN"))?
        } else {
            d.get("admin_public_key")
        }
    } else if let Some(c) = &c {
        if let Some(id) = &device {
            let d = store::object(&mut *db, chain_id, "device", id)
                .await?
                .ok_or_else(|| err("TOKEN_SIGNATURE_INVALID"))?;
            device_state = Some((
                d.clone(),
                sqlx::query_scalar::<_, String>(
                    "SELECT status FROM v3_registry WHERE chain_id=? AND device_id=?",
                )
                .bind(chain_id)
                .bind(id)
                .fetch_optional(&mut *db)
                .await?
                .unwrap_or_else(|| "unknown".into()),
            ));
            s(&d, "device_public_key").to_owned()
        } else {
            s(&c.parameters, "admin_public_key").to_owned()
        }
    } else if let Some(key) = proposed_key {
        key.to_owned()
    } else {
        return Err(err("TOKEN_SIGNATURE_INVALID"));
    };
    if !verify_signed_json(&key, s(&token, "signature"), &token, CTX_CAPABILITY).unwrap_or(false) {
        return Err(err("TOKEN_SIGNATURE_INVALID"));
    }
    if cfg.privacy["replay_protection"]["mode"] == "restart_barrier" {
        let barrier: i64 =
            sqlx::query_scalar("SELECT barrier_ms FROM v3_restart_barrier WHERE id=1")
                .fetch_one(&mut *db)
                .await?;
        if issued < (barrier as u64) {
            return Err(
                err("TOKEN_NOT_YET_VALID").context(json!({"retry_after_ms":barrier as u64-issued}))
            );
        }
    }
    // Durable reservation is committed by the caller even if lifecycle/operation validation fails.
    sqlx::query("DELETE FROM v3_nonces WHERE expires_at_ms < ?")
        .bind(t as i64)
        .execute(&mut *db)
        .await?;
    let result=sqlx::query("INSERT OR IGNORE INTO v3_nonces(chain_id,signer_kind,device_id,nonce,expires_at_ms) VALUES(?,?,?,?,?)").bind(chain_id).bind(s(&token,"signer_kind")).bind(device.as_deref().unwrap_or("")).bind(s(&token,"nonce")).bind((expires+60000) as i64).execute(&mut *db).await?;
    if result.rows_affected() != 1 {
        return Err(err("TOKEN_REPLAYED"));
    }
    if let Some((d, status)) = device_state {
        let c = c.as_ref().unwrap();
        if n(&d, "generation") != c.generation() {
            return Err(err("GENERATION_MISMATCH"));
        }
        if status == "revoked" {
            return Err(err("DEVICE_REVOKED"));
        }
        if status == "unknown" {
            return Err(err("DEVICE_UNKNOWN"));
        }
        if status == "pending_keys"
            && !matches!(
                route,
                "parameters_get" | "epochs_get" | "epoch_get" | "own_envelopes" | "ack"
            )
        {
            return Err(err("DEVICE_PENDING_KEYS"));
        }
    }
    rate(
        db,
        cfg,
        "authorized_signer",
        &format!(
            "{chain_id}:{}:{}",
            s(&token, "signer_kind"),
            device.as_deref().unwrap_or("")
        ),
    )
    .await?;
    Ok(Auth { token, device })
}
pub async fn signing_key(db: &mut SqliteConnection, c: &Chain, v: &Value) -> Result<String> {
    if s(v, "signer_kind") == "admin" {
        return Ok(s(&c.parameters, "admin_public_key").into());
    }
    let id = s(v, "signer_device_id");
    active_device(db, c, id).await
}
pub async fn check_state(
    db: &mut SqliteConnection,
    c: &Chain,
    auth: &Auth,
    route: &str,
) -> Result<()> {
    let Some(id) = &auth.device else {
        return Ok(());
    };
    let d = store::object(&mut *db, &c.chain_id, "device", id)
        .await?
        .ok_or_else(|| err("DEVICE_UNKNOWN"))?;
    if n(&d, "generation") != c.generation() {
        return Err(err("GENERATION_MISMATCH"));
    }
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM v3_registry WHERE chain_id=? AND device_id=?")
            .bind(&c.chain_id)
            .bind(id)
            .fetch_optional(db)
            .await?;
    match status.as_deref() {
        Some("revoked") => Err(err("DEVICE_REVOKED")),
        Some("pending_keys")
            if !matches!(
                route,
                "parameters_get" | "epochs_get" | "epoch_get" | "own_envelopes" | "ack"
            ) =>
        {
            Err(err("DEVICE_PENDING_KEYS"))
        }
        Some(_) => Ok(()),
        None => Err(err("DEVICE_UNKNOWN")),
    }
}
pub async fn active_device(db: &mut SqliteConnection, c: &Chain, id: &str) -> Result<String> {
    let d = store::object(&mut *db, &c.chain_id, "device", id)
        .await?
        .ok_or_else(|| err("DEVICE_UNKNOWN"))?;
    if n(&d, "generation") != c.generation() {
        return Err(err("GENERATION_MISMATCH"));
    }
    let status: String =
        sqlx::query_scalar("SELECT status FROM v3_registry WHERE chain_id=? AND device_id=?")
            .bind(&c.chain_id)
            .bind(id)
            .fetch_one(db)
            .await?;
    if status != "active" {
        return Err(err(if status == "revoked" {
            "DEVICE_REVOKED"
        } else {
            "DEVICE_PENDING_KEYS"
        }));
    }
    Ok(s(&d, "device_public_key").into())
}
