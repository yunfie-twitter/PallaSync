use pallasync_server::crypto::{jcs, verify::*};

#[test]
fn archived_operator_policy_preserves_its_v3_signature_and_exact_markdown() {
    let p = jcs::parse(include_bytes!("../operator/api.yunfi.f5.si/privacy.json")).unwrap();
    let md = include_bytes!("../operator/api.yunfi.f5.si/privacy.md");
    let public_key = include_str!("../operator/api.yunfi.f5.si/relay-public-key.txt").trim();
    assert!(valid_ed_key(public_key));
    assert_eq!(
        p["relay_key_id"],
        hash_bytes(&decode(public_key, Some(32)).unwrap())
    );
    assert_eq!(p["markdown_sha256"], hash_bytes(md));
    assert_eq!(p["relay_origin"], "https://api.yunfi.f5.si");
    assert!(
        verify_signature(
            public_key,
            p["relay_signature"].as_str().unwrap(),
            &signing_bytes(&p, CTX_PRIVACY, "relay_signature")
        )
        .unwrap()
    );
}
