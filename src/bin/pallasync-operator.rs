//! Offline §7.13 policy authoring with the server's exact validator and §17.9 relay key.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use pallasync_server::{
    api::error::now,
    config::RelayConfig,
    crypto::{jcs, verify::*},
};
use serde_json::Value;
use std::{fs, io::Read, path::Path};

fn read_public(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1048577)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1048576 {
        return Err("Policy exceeds 1 MiB".into());
    }
    Ok(bytes)
}

fn key_from_stdin() -> Result<SigningKey, String> {
    let mut input = String::new();
    std::io::stdin()
        .take(65)
        .read_to_string(&mut input)
        .map_err(|_| "Invalid seed input")?;
    let mut bytes = decode(input.trim_end_matches(['\r', '\n']), Some(32))
        .map_err(|_| "Expected a canonical Base64URL 32-byte seed on stdin")?;
    let key = SigningKey::from_bytes(bytes.as_slice().try_into().unwrap());
    bytes.fill(0);
    Ok(key)
}

fn validate(
    key: SigningKey,
    md: Vec<u8>,
    p: Value,
    quota: Option<u64>,
) -> Result<RelayConfig, String> {
    RelayConfig::new(key, md, p, quota)
        .map_err(|e| format!("Policy rejected by server validator: {}", e.code))
}

fn sign(draft: &Path, output: &Path, quota: Option<u64>) -> Result<(), String> {
    if output.exists() {
        return Err(
            "Policy directory already exists; refusing to overwrite a published revision".into(),
        );
    }
    let key = key_from_stdin()?;
    let draft_md = read_public(&draft.join("privacy.md"))?;
    let mut p = jcs::parse(&read_public(&draft.join("privacy.json"))?).map_err(str::to_owned)?;
    if !p.is_object() {
        return Err("Policy draft must be an object".into());
    }
    // A new deployment begins at revision 1. Reruns verify the existing signed policy.
    for name in [
        "relay_signature",
        "relay_key_id",
        "disclosure_id",
        "revision",
        "published_at_ms",
        "effective_at_ms",
        "markdown_sha256",
    ] {
        if p.get(name).is_some() {
            return Err(format!("Draft must not supply derived field: {name}"));
        }
    }
    let timestamp = now();
    let id = uuid::Uuid::new_v4().to_string();
    let key_id = hash_bytes(key.verifying_key().as_bytes());
    let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let header = format!(
        "# Relay privacy policy\n\nRevision: 1  \nDisclosure ID: {id}  \nPublished / effective (UTC): {}  \nPublished / effective (Unix milliseconds): {timestamp}  \nRelay key ID: {key_id}\n\n",
        chrono::DateTime::from_timestamp_millis(timestamp as i64)
            .unwrap()
            .to_rfc3339()
    );
    let md = [header.as_bytes(), &draft_md].concat();
    p["revision"] = 1.into();
    p["disclosure_id"] = id.into();
    p["published_at_ms"] = timestamp.into();
    p["effective_at_ms"] = timestamp.into();
    p["relay_key_id"] = key_id.into();
    p["markdown_sha256"] = hash_bytes(&md).into();
    sign_relay(&key, &mut p, CTX_PRIVACY).map_err(str::to_owned)?;
    let cfg = validate(key, md, p, quota)?;
    let parent = output.parent().ok_or("Output directory needs a parent")?;
    let temporary = parent.join(format!(".policy-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&temporary).map_err(|e| e.to_string())?;
    let result = (|| {
        fs::write(temporary.join("privacy.md"), cfg.markdown.as_slice())?;
        fs::write(
            temporary.join("privacy.json"),
            serde_json::to_vec_pretty(&cfg.privacy)?,
        )?;
        fs::write(
            temporary.join("relay-public-key.txt"),
            format!("{public_key}\n"),
        )?;
        // These are public documents. The server's fixed container UID must read the bind mount.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))?;
            for name in ["privacy.md", "privacy.json", "relay-public-key.txt"] {
                fs::set_permissions(temporary.join(name), fs::Permissions::from_mode(0o644))?;
            }
        }
        fs::rename(&temporary, output)
    })();
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(e.to_string());
    }
    println!("Signed revision 1; relay_key_id={}", cfg.key_id);
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "Usage: pallasync-operator sign DRAFT_DIR POLICY_DIR QUOTA|none\n       pallasync-operator verify POLICY_DIR QUOTA|none\nSeed is read from stdin only; it is never printed.";
    let quota = |s: &str| -> Result<Option<u64>, String> {
        if s == "none" {
            Ok(None)
        } else {
            s.parse().map(Some).map_err(|_| "Invalid quota".into())
        }
    };
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["sign", draft, output, q] => sign(Path::new(draft), Path::new(output), quota(q)?),
        ["verify", path, q] => {
            let key = key_from_stdin()?;
            let path = Path::new(path);
            let p = jcs::parse(&read_public(&path.join("privacy.json"))?).map_err(str::to_owned)?;
            let cfg = validate(key, read_public(&path.join("privacy.md"))?, p, quota(q)?)?;
            println!(
                "Verified revision {}; relay_key_id={}",
                cfg.privacy["revision"], cfg.key_id
            );
            Ok(())
        }
        _ => Err(usage.into()),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
