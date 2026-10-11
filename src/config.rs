//! §7.13/§17.12: effective operator documents are inputs, never invented defaults.
use crate::{
    api::{
        error::{Result, err, now},
        wire::*,
    },
    crypto::{jcs, verify::*},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{env, sync::Arc};

#[derive(Clone)]
pub struct RelayConfig {
    pub key: Arc<SigningKey>,
    pub origin: String,
    pub key_id: String,
    pub privacy: Value,
    pub markdown: Arc<Vec<u8>>,
    pub max_bytes: Option<u64>,
    pub shutdown_at_ms: Option<u64>,
    pub migration_origin: Option<String>,
    pub stop_writes: bool,
}
impl RelayConfig {
    pub fn from_env() -> std::result::Result<Self, String> {
        let seed=env::var("PALLASYNC_RELAY_SIGNING_SEED").map_err(|_|"PALLASYNC_RELAY_SIGNING_SEED is required; inject an independently protected operator key")?;
        let seed = decode(&seed, Some(32)).map_err(str::to_owned)?;
        let key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
        let md = std::fs::read(
            env::var("PALLASYNC_PRIVACY_MARKDOWN")
                .map_err(|_| "PALLASYNC_PRIVACY_MARKDOWN is required")?,
        )
        .map_err(|e| e.to_string())?;
        let disclosure = std::fs::read(
            env::var("PALLASYNC_PRIVACY_JSON").map_err(|_| "PALLASYNC_PRIVACY_JSON is required")?,
        )
        .map_err(|e| e.to_string())?;
        let privacy = jcs::parse(&disclosure).map_err(str::to_owned)?;
        let max_bytes = env::var("PALLASYNC_QUOTA_BYTES")
            .ok()
            .map(|v| v.parse::<u64>())
            .transpose()
            .map_err(|_| "Invalid quota")?;
        let mut cfg = Self::new(key, md, privacy, max_bytes)
            .map_err(|e| format!("Operator disclosure rejected: {}", e.code))?;
        cfg.shutdown_at_ms = env::var("PALLASYNC_SHUTDOWN_AT_MS")
            .ok()
            .map(|s| s.parse::<u64>())
            .transpose()
            .map_err(|_| "Invalid shutdown time")?;
        cfg.migration_origin = env::var("PALLASYNC_MIGRATION_ORIGIN")
            .ok()
            .filter(|s| !s.is_empty());
        cfg.stop_writes = match env::var("PALLASYNC_STOP_WRITES").as_deref() {
            Ok("true") => true,
            Ok("false") | Err(_) => false,
            _ => return Err("Invalid write-stop setting".into()),
        };
        if cfg.shutdown_at_ms.is_some_and(|t| t > jcs::MAX_INTEGER)
            || cfg
                .migration_origin
                .as_ref()
                .is_some_and(|s| !valid_origin(s))
        {
            return Err("Invalid relay notice".into());
        }
        Ok(cfg)
    }
    pub fn new(
        key: SigningKey,
        markdown: Vec<u8>,
        privacy: Value,
        max_bytes: Option<u64>,
    ) -> Result<Self> {
        let schema: Value =
            serde_json::from_str(include_str!("../docs/privacy.schema.json")).unwrap();
        if markdown.len() > 1048576
            || !std::str::from_utf8(&markdown).is_ok_and(|s| !s.starts_with('\u{feff}'))
            || jcs::canonicalize_json(&privacy).unwrap().len() > 1048576
            || !schema_valid(&schema, &schema, &privacy)
        {
            return Err(err("INVALID_FIELD"));
        }
        let origin = s(&privacy, "relay_origin").to_owned();
        let key_id = hash_bytes(key.verifying_key().as_bytes());
        if !valid_origin(&origin)
            || !valid_ed_key(&URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()))
            || privacy["relay_key_id"] != key_id
            || privacy["markdown_sha256"] != hash_bytes(&markdown)
            || n(&privacy, "published_at_ms") > n(&privacy, "effective_at_ms")
            || n(&privacy, "effective_at_ms") > now()
            || privacy["durability_tier"] != "single-durable"
            || !["durable", "restart_barrier"].contains(&s(&privacy["replay_protection"], "mode"))
            || privacy["deletion"]["assurance"] != "backup-expiry"
            || privacy["backups"]["enabled"] != false
        {
            return Err(err("INVALID_FIELD"));
        }
        // This implementation acknowledges one local fsynced SQLite store, without backups or storage-key shredding.
        if privacy["copies"]["replica"]["present"] != false
            || privacy["copies"]["backup"]["present"] != false
            || !privacy["deletion"]["backup_delete_max_ms"].is_null()
            || !privacy["deletion"]["key_destroy_max_ms"].is_null()
        {
            return Err(err("INVALID_FIELD"));
        }
        for name in [
            "active_store",
            "wal",
            "snapshot_store",
            "staging",
            "cache",
            "attestations",
            "deletion_ledger",
        ] {
            if privacy["copies"][name]["present"] != true {
                return Err(err("INVALID_FIELD"));
            }
        }
        for (name, c) in privacy["copies"].as_object().unwrap() {
            if ["active_store", "wal", "snapshot_store", "staging"].contains(&name.as_str())
                && c["content"] != "ciphertext"
            {
                return Err(err("INVALID_FIELD"));
            }
            if c["present"] != true {
                continue;
            }
            if c["content"] == "ciphertext" {
                let d = n(&c["after_delete"], "max_ms");
                if c["after_delete"]["mode"] != "erase"
                    || d == 0
                    || (["active_store", "wal", "snapshot_store"].contains(&name.as_str())
                        && d > n(&privacy["deletion"], "active_delete_max_ms"))
                {
                    return Err(err("INVALID_FIELD"));
                }
            }
        }
        if privacy["copies"]["active_store"]["retention"]["mode"] != "until_chain_deletion" {
            return Err(err("INVALID_FIELD"));
        }
        let quota = &privacy["quota"];
        if ![
            "record",
            "snapshot",
            "envelope",
            "device_meta",
            "receipt",
            "transparency",
            "control",
        ]
        .iter()
        .all(|component| {
            a(quota, "counted_components")
                .iter()
                .any(|v| v == component)
        }) {
            return Err(err("INVALID_FIELD"));
        }
        if quota["maximum_bytes"]
            .as_u64()
            .is_some_and(|m| m < n(quota, "minimum_bytes"))
            || max_bytes.is_some_and(|m| {
                m > jcs::MAX_INTEGER
                    || m < n(quota, "minimum_bytes")
                    || quota["maximum_bytes"].as_u64().is_some_and(|v| m > v)
            })
            || (max_bytes.is_none() && quota["allow_unconfigured"] != true)
        {
            return Err(err("INVALID_FIELD"));
        }
        for (scope, rate, burst) in [
            ("authorized_signer", 120, 30),
            ("record_upload_device", 30, 10),
            ("enrollment_source_ip", 6, 3),
            ("enrollment_offer", 3, 1),
        ] {
            if n(&privacy["rate_limits"][scope], "requests_per_minute") > rate
                || n(&privacy["rate_limits"][scope], "burst") > burst
            {
                return Err(err("INVALID_FIELD"));
            }
        }
        if n(
            &privacy["rate_limits"]["public_document_ip"],
            "requests_per_minute",
        ) < 2 * n(
            &privacy["rate_limits"]["authorized_signer"],
            "requests_per_minute",
        ) {
            return Err(err("INVALID_FIELD"));
        }
        if a(&privacy["metadata"], "retained_fields").is_empty()
            && (!a(&privacy["metadata"], "purposes").is_empty()
                || !a(&privacy["metadata"], "recipients").is_empty()
                || privacy["metadata"]["retention"]["mode"] != "not_retained")
        {
            return Err(err("INVALID_FIELD"));
        }
        // Persisted rate buckets contain only IP digests and their last update time, but these remain operational metadata.
        // No expiry service is claimed for those indexes: an operator must disclose their actual indefinite retention.
        if !["ip", "timing"].iter().all(|field| {
            a(&privacy["metadata"], "retained_fields")
                .iter()
                .any(|v| v == field)
        }) || privacy["metadata"]["retention"]["mode"] != "indefinite"
            || a(&privacy["metadata"], "purposes").is_empty()
            || a(&privacy["metadata"], "recipients").is_empty()
            || privacy["copies"]["cache"]["content"] != "metadata"
            || privacy["copies"]["cache"]["retention"]["mode"] != "indefinite"
            || privacy["copies"]["cache"]["after_delete"]["mode"] != "retain_metadata"
            || !privacy["copies"]["cache"]["after_delete"]["max_ms"].is_null()
        {
            return Err(err("INVALID_FIELD"));
        }
        for path in [
            "/operator/contact_url",
            "/change_notice/notice_url",
            "/change_notice/archive_url",
        ] {
            if !privacy
                .pointer(path)
                .and_then(Value::as_str)
                .is_some_and(valid_url)
            {
                return Err(err("INVALID_FIELD"));
            }
        }
        validate_strings(&privacy)?;
        let input = signing_bytes(&privacy, CTX_PRIVACY, "relay_signature");
        if !verify_signature(
            &URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
            s(&privacy, "relay_signature"),
            &input,
        )
        .unwrap_or(false)
        {
            return Err(err("OBJECT_SIGNATURE_INVALID"));
        }
        Ok(Self {
            key: Arc::new(key),
            origin,
            key_id,
            privacy,
            markdown: Arc::new(markdown),
            max_bytes,
            shutdown_at_ms: None,
            migration_origin: None,
            stop_writes: false,
        })
    }
    pub fn limits(&self) -> &Value {
        &self.privacy["limits"]
    }
    pub fn health(&self) -> Value {
        json!({"protocol":"pallasync/3","relay_origin":self.origin,"server_time_ms":now(),"durability_tier":"single-durable","limits":self.limits(),"shutdown_at_ms":self.shutdown_at_ms,"migration_origin":self.migration_origin,"relay_public_key":URL_SAFE_NO_PAD.encode(self.key.verifying_key().as_bytes()),"relay_key_id":self.key_id})
    }
    pub fn write_guard(&self) -> Result<()> {
        if self.stop_writes || self.shutdown_at_ms.is_some_and(|t| now() >= t) {
            return Err(err("RELAY_SHUTTING_DOWN").context(json!({"shutdown_at_ms":self.shutdown_at_ms,"migration_origin":self.migration_origin})));
        }
        Ok(())
    }
}
pub fn valid_url(s: &str) -> bool {
    s.is_ascii()
        && s.len() <= 4096
        && url::Url::parse(s).is_ok_and(|u| {
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none()
        })
}
pub fn valid_origin(s: &str) -> bool {
    valid_url(s)
        && url::Url::parse(s).is_ok_and(|u| {
            u.path() == "/" && u.query().is_none() && u.origin().ascii_serialization() == s
        })
}
fn validate_strings(v: &Value) -> Result<()> {
    match v {
        Value::String(s) => {
            if s.len() > 4096 || s.chars().count() > 4096 {
                return Err(err("INVALID_FIELD"));
            }
        }
        Value::Object(o) => {
            for v in o.values() {
                validate_strings(v)?
            }
        }
        Value::Array(a) => {
            for v in a {
                validate_strings(v)?
            }
        }
        _ => {}
    }
    Ok(())
}
// Closed evaluator for the exact vendored schema (no remote refs or coercion).
fn schema_valid(root: &Value, schema: &Value, v: &Value) -> bool {
    if let Some(r) = schema["$ref"].as_str() {
        return root
            .pointer(&r[1..])
            .is_some_and(|s| schema_valid(root, s, v));
    }
    for (k, count) in [("anyOf", false), ("oneOf", true)] {
        if let Some(a) = schema[k].as_array() {
            let n = a.iter().filter(|s| schema_valid(root, s, v)).count();
            if (count && n != 1) || (!count && n == 0) {
                return false;
            }
        }
    }
    if schema.get("const").is_some_and(|c| c != v)
        || schema["enum"].as_array().is_some_and(|a| !a.contains(v))
    {
        return false;
    }
    if let Some(t) = schema["type"].as_str()
        && !match t {
            "object" => v.is_object(),
            "array" => v.is_array(),
            "integer" => v.as_u64().is_some(),
            "string" => v.is_string(),
            "boolean" => v.is_boolean(),
            "null" => v.is_null(),
            _ => false,
        }
    {
        return false;
    }
    if let Some(n) = v.as_u64()
        && (schema["minimum"].as_u64().is_some_and(|min| n < min)
            || schema["maximum"].as_u64().is_some_and(|max| n > max))
    {
        return false;
    }
    if let Some(s) = v.as_str() {
        let n = s.chars().count() as u64;
        if schema["minLength"].as_u64().is_some_and(|min| n < min)
            || schema["maxLength"].as_u64().is_some_and(|max| n > max)
            || schema["pattern"]
                .as_str()
                .is_some_and(|p| !regex::Regex::new(p).unwrap().is_match(s))
        {
            return false;
        }
        if schema["pattern"] == "^[A-Za-z0-9_-]{43}$" && decode(s, Some(32)).is_err() {
            return false;
        }
        if schema["pattern"] == "^[A-Za-z0-9_-]{86}$" && decode(s, Some(64)).is_err() {
            return false;
        }
    }
    if let Some(o) = v.as_object() {
        if schema["required"]
            .as_array()
            .is_some_and(|a| a.iter().any(|k| !o.contains_key(k.as_str().unwrap())))
        {
            return false;
        }
        for (k, v) in o {
            if let Some(p) = schema["properties"].get(k) {
                if !schema_valid(root, p, v) {
                    return false;
                }
            } else if schema["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(a) = v.as_array() {
        let n = a.len() as u64;
        if schema["minItems"].as_u64().is_some_and(|min| n < min)
            || schema["maxItems"].as_u64().is_some_and(|max| n > max)
        {
            return false;
        }
        for (i, v) in a.iter().enumerate() {
            if schema
                .get("items")
                .is_some_and(|s| !schema_valid(root, s, v))
                || (schema["uniqueItems"] == true && a[..i].contains(v))
            {
                return false;
            }
        }
    }
    true
}
