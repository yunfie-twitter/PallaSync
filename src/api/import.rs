use super::{
    auth::Auth,
    domain::*,
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub async fn stage(
    db: &mut SqliteConnection,
    cfg: &RelayConfig,
    v: &Value,
) -> Result<(Value, Chain)> {
    fields(
        v,
        &[
            ("parameters_history", "array"),
            ("epoch_history", "array"),
            ("device_history", "array"),
            ("envelopes", "array"),
            ("compactions", "array"),
        ],
        &[],
    )?;
    if a(v, "parameters_history").is_empty() || a(v, "epoch_history").is_empty() {
        return Err(err("IMPORT_CONFLICT"));
    }
    let p = a(v, "parameters_history").last().unwrap();
    let e = a(v, "epoch_history").last().unwrap();
    let chain = s(p, "chain_id");
    let admin = s(p, "admin_public_key");
    let current = store::load(&mut *db, chain).await?;
    if let Some(c) = &current
        && (c.parameters_hash() != object_hash(p)
            || c.epoch_hash() != object_hash(e)
            || s(&c.parameters, "admin_public_key") != admin)
    {
        return Err(err("IMPORT_CONFLICT"));
    }
    let staged_head = sqlx::query("SELECT parameters,epoch FROM v3_imports WHERE chain_id=?")
        .bind(chain)
        .fetch_optional(&mut *db)
        .await?;
    if let Some(staged_head) = staged_head
        && (store::value(staged_head.get("parameters")) != *p
            || store::value(staged_head.get("epoch")) != *e)
    {
        return Err(err("IMPORT_CONFLICT"));
    }
    for (kind, key) in [
        ("parameters", "parameters_history"),
        ("epoch", "epoch_history"),
        ("device", "device_history"),
        ("envelope", "envelopes"),
        ("compaction", "compactions"),
    ] {
        for obj in a(v, key) {
            validate(obj, kind)?;
            if s(obj, "chain_id") != chain {
                return Err(err("IMPORT_CONFLICT"));
            }
        }
    }
    for p in a(v, "parameters_history") {
        if s(p, "admin_public_key") != admin {
            return Err(err("IMPORT_CONFLICT"));
        }
        verify(p, admin, CTX_PARAMETERS)?;
        if n(p, "generation") > 0 {
            let prev = store::object(
                &mut *db,
                chain,
                "parameters",
                &(n(p, "generation") - 1).to_string(),
            )
            .await?;
            if prev
                .as_ref()
                .is_some_and(|prev| s(p, "previous_parameters_hash") != object_hash(prev))
            {
                return Err(err("IMPORT_CONFLICT"));
            }
        }
        store::put_object(&mut *db, chain, "parameters", p, None).await?;
    }
    // Resolve the certificate DAG in bounded passes; no self/circular graph can create membership.
    let mut unresolved = a(v, "device_history").to_vec();
    let mut verified = std::collections::HashMap::<String, Value>::new();
    while !unresolved.is_empty() {
        let before = unresolved.len();
        let mut next = Vec::new();
        for d in unresolved {
            let cert = &d["enrollment"];
            let key = if s(cert, "signer_kind") == "admin" {
                Some(admin.to_owned())
            } else {
                let id = s(cert, "signer_device_id");
                if let Some(signer) = verified.get(id) {
                    if n(signer, "generation") != n(&d, "generation") {
                        return Err(err("IMPORT_CONFLICT"));
                    }
                    Some(s(signer, "device_public_key").into())
                } else {
                    store::object(&mut *db, chain, "device", id)
                        .await?
                        .filter(|d2| n(d2, "generation") == n(&d, "generation"))
                        .map(|d2| s(&d2, "device_public_key").into())
                }
            };
            if let Some(key) = key {
                verify(cert, &key, CTX_ENROLLMENT)
                    .map_err(|_| err("ENROLLMENT_CERTIFICATE_INVALID"))?;
                verify(&d, s(&d, "device_public_key"), CTX_DEVICE_RECORD)?;
                store::put_object(&mut *db, chain, "device", &d, None).await?;
                verified.insert(s(&d, "device_id").into(), d);
            } else {
                next.push(d)
            }
        }
        if next.len() == before {
            return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
        }
        unresolved = next;
    }
    for epoch in a(v, "epoch_history") {
        let num = n(epoch, "epoch");
        if num > 0 {
            let previous = store::object(&mut *db, chain, "epoch", &(num - 1).to_string()).await?;
            if previous
                .as_ref()
                .is_some_and(|previous| s(epoch, "previous_epoch_hash") != object_hash(previous))
            {
                return Err(err("EPOCH_CHAIN_INVALID"));
            }
        }
        let key = historical_key(&mut *db, chain, admin, epoch).await?;
        verify(epoch, &key, CTX_EPOCH)?;
        for id in a(epoch, "members") {
            let d = store::object(&mut *db, chain, "device", id.as_str().unwrap()).await?;
            if d.as_ref()
                .is_some_and(|d| n(d, "generation") != n(epoch, "generation"))
            {
                return Err(err("IMPORT_CONFLICT"));
            }
        }
        store::put_object(&mut *db, chain, "epoch", epoch, None).await?;
    }
    for env in a(v, "envelopes") {
        let epoch = store::object(&mut *db, chain, "epoch", &n(env, "epoch").to_string())
            .await?
            .ok_or_else(|| err("IMPORT_CONFLICT"))?;
        for k in [
            "generation",
            "epoch",
            "epoch_commitment",
            "previous_epoch_hash",
        ] {
            if env[k] != epoch[k] {
                return Err(err("IMPORT_CONFLICT"));
            }
        }
        if s(env, "recipient_kind") == "recovery"
            && object_hash(env) != s(&epoch, "recovery_envelope_hash")
        {
            return Err(err("IMPORT_CONFLICT"));
        }
        let key = historical_key(&mut *db, chain, admin, env).await?;
        verify(env, &key, CTX_ENVELOPE)?;
        store::put_object(&mut *db, chain, "envelope", env, None).await?;
    }
    for comp in a(v, "compactions") {
        let d = store::object(&mut *db, chain, "device", s(comp, "device_id"))
            .await?
            .ok_or_else(|| err("IMPORT_CONFLICT"))?;
        verify(comp, s(&d, "device_public_key"), CTX_COMPACTION)?;
        store::put_object(&mut *db, chain, "compaction", comp, None).await?;
    }
    let staged: Option<String> =
        sqlx::query_scalar("SELECT log_id FROM v3_imports WHERE chain_id=?")
            .bind(chain)
            .fetch_optional(&mut *db)
            .await?;
    let log_id = staged.unwrap_or_else(store::new_id);
    sqlx::query("INSERT INTO v3_imports(chain_id,log_id,parameters,epoch) VALUES(?,?,?,?) ON CONFLICT(chain_id) DO NOTHING").bind(chain).bind(&log_id).bind(store::text(p)).bind(store::text(e)).execute(&mut *db).await?;
    let mut c =
        current.unwrap_or_else(|| Chain::new(p.clone(), e.clone(), cfg, Some(log_id.clone())));
    if store::load(&mut *db, chain).await?.is_none() {
        c.writable = false;
        store::save(&mut *db, &c, cfg).await?
    }
    store::quota(db, chain, cfg).await?;
    Ok((
        json!({"chain_id":chain,"state":"staged","log_id":log_id}),
        c,
    ))
}
async fn historical_key(
    db: &mut SqliteConnection,
    chain: &str,
    admin: &str,
    v: &Value,
) -> Result<String> {
    if s(v, "signer_kind") == "admin" {
        return Ok(admin.into());
    }
    let d = store::object(db, chain, "device", s(v, "signer_device_id"))
        .await?
        .ok_or_else(|| err("IMPORT_CONFLICT"))?;
    if n(&d, "generation") != n(v, "generation") {
        return Err(err("IMPORT_CONFLICT"));
    }
    Ok(s(&d, "device_public_key").into())
}
pub async fn reseed(
    db: &mut SqliteConnection,
    old: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    v: &Value,
) -> Result<Value> {
    auth.require_admin()?;
    fields(
        v,
        &[
            ("parameters", "object"),
            ("epoch", "object"),
            ("envelopes", "array"),
            ("compaction", "object"),
            ("admin_operation", "object"),
            ("device_records", "array"),
        ],
        &[],
    )?;
    let p = &v["parameters"];
    validate(p, "parameters")?;
    let id = s(&v["admin_operation"], "operation_id");
    if let Some(r) = store::outcomes(&mut *db, &old.chain_id, "reseed", id, v).await? {
        return Ok(r);
    }
    admin_operation(
        &mut *db,
        old,
        &v["admin_operation"],
        "reseed",
        &target(
            v,
            &[
                "parameters",
                "epoch",
                "envelopes",
                "compaction",
                "device_records",
            ],
        ),
    )
    .await?;
    if s(p, "chain_id") != old.chain_id
        || s(p, "admin_public_key") != s(&old.parameters, "admin_public_key")
        || n(p, "generation") != old.generation() + 1
        || s(p, "previous_parameters_hash") != old.parameters_hash()
    {
        return Err(err("GENERATION_MISMATCH"));
    }
    verify(p, s(p, "admin_public_key"), CTX_PARAMETERS)?;
    if a(v, "device_records").is_empty()
        || a(v, "device_records").len() > n(cfg.limits(), "max_devices") as usize
    {
        return Err(err("MEMBER_SET_MISMATCH"));
    }
    let imported = sqlx::query("SELECT log_id,parameters,epoch FROM v3_imports WHERE chain_id=?")
        .bind(&old.chain_id)
        .fetch_optional(&mut *db)
        .await?
        .ok_or_else(|| err("IMPORT_CONFLICT"))?;
    if store::value(imported.get("parameters")) != old.parameters
        || store::value(imported.get("epoch")) != old.epoch
    {
        return Err(err("CAS_MISMATCH"));
    }
    let mut c = Chain::new(
        p.clone(),
        old.epoch.clone(),
        cfg,
        Some(imported.get("log_id")),
    );
    // Healthy transparency does not reset when data log_id changes (§7.12.2).
    c.transparency_id = old.transparency_id.clone();
    c.transparency_index = old.transparency_index;
    c.transparency_hash = old.transparency_hash.clone();
    let mut rs = Vec::new();
    for d in a(v, "device_records") {
        device(&mut *db, &c, d, None, true).await?;
        if s(&d["enrollment"], "signer_kind") != "admin" {
            return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
        }
    }
    // Previously staged authority objects gain target-storage receipts on commit, without impersonating source receipts.
    for kind in ["parameters", "device", "envelope", "epoch", "admin"] {
        let ids:Vec<String>=sqlx::query_scalar("SELECT object_id FROM v3_objects WHERE chain_id=? AND kind=? AND log_id IS NULL ORDER BY CASE WHEN kind IN ('parameters','epoch') THEN CAST(object_id AS INTEGER) ELSE object_id END").bind(&old.chain_id).bind(kind).fetch_all(&mut *db).await?;
        for id in ids {
            let obj = store::object(&mut *db, &old.chain_id, kind, &id)
                .await?
                .unwrap();
            let (entry, r) = store::append(&mut *db, &mut c, cfg, kind, &obj).await?;
            rs.push(r);
            if kind == "device" {
                let revoked=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND kind='epoch' AND EXISTS(SELECT 1 FROM json_each(json_extract(body,'$.revoked_device_ids')) WHERE value=?)").bind(&old.chain_id).bind(&id).fetch_one(&mut *db).await?>0;
                register(
                    &mut *db,
                    &c,
                    &obj,
                    n(&entry, "relay_seq"),
                    if revoked || n(&obj, "generation") != old.generation() {
                        "revoked"
                    } else {
                        "active"
                    },
                )
                .await?;
            }
        }
    }
    if s(&v["epoch"], "reason") != "reseed" {
        return Err(err("EPOCH_CHAIN_INVALID"));
    }
    bundle(
        &mut *db,
        &c,
        &v["epoch"],
        a(v, "envelopes"),
        a(v, "device_records"),
        false,
        true,
    )
    .await?;
    rs.push(
        store::append(&mut *db, &mut c, cfg, "parameters", p)
            .await?
            .1,
    );
    let (_, r) = commit_epoch(
        &mut *db,
        &mut c,
        cfg,
        EpochCommit {
            epoch: &v["epoch"],
            envelopes: a(v, "envelopes"),
            staged: a(v, "device_records"),
            admin: Some(&v["admin_operation"]),
            genesis: false,
        },
    )
    .await?;
    rs.extend(r);
    let comp = &v["compaction"];
    if n(comp, "covered_through_seq") != 0 {
        return Err(err("COMPACTION_UNSAFE"));
    }
    compaction(&mut *db, &c, comp, a(v, "device_records")).await?;
    rs.push(
        store::append(&mut *db, &mut c, cfg, "compaction", comp)
            .await?
            .1,
    );
    let mut response = c.result();
    response["upload_receipts"] = rs.into();
    store::outcome(&mut *db, &c.chain_id, "reseed", id, v, &response).await?;
    sqlx::query("DELETE FROM v3_imports WHERE chain_id=?")
        .bind(&c.chain_id)
        .execute(&mut *db)
        .await?;
    *old = c;
    Ok(response)
}
