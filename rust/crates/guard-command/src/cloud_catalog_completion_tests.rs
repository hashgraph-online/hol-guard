use super::*;

#[test]
fn completion_is_bound_fresh_durable_and_rejects_races() {
    let home = home();
    let view = prepare(home.path(), 166);
    let mut request = json!({"guard_home":home.path(),"token":view["token"],
        "observation":observation(home.path()),
        "origin":"https://example.test/api/guard/runtime/extension-catalog/sync-v2",
        "credential_binding":"d".repeat(64),
        "identity":{"ownerUserId":"owner","workspaceId":"workspace","deviceId":"device","runtimeId":"runtime"}});
    // Produce an exact current UTC timestamp without introducing a test clock
    // parameter into the production acceptance boundary.
    request["action"] = json!("completion_begin");
    let begun = evaluate(&request);
    assert!(begun.get("error").is_none(), "{begun}");
    let overlapping = evaluate(&request);
    assert!(overlapping.get("error").is_none(), "{overlapping}");
    assert_ne!(
        begun["payload"]["idempotencyKey"],
        overlapping["payload"]["idempotencyKey"]
    );
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let unix = clock.as_secs();
    let mut days = unix / 86400;
    let mut year = 1970;
    let leap = |y| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    loop {
        let n = if leap(year) { 366 } else { 365 };
        if days < n {
            break;
        }
        days -= n;
        year += 1;
    }
    let mut month = 1;
    loop {
        let n = match month {
            2 if leap(year) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if days < n {
            break;
        }
        days -= n;
        month += 1;
    }
    let date = format!(
        "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        days + 1,
        unix % 86400 / 3600,
        unix % 3600 / 60,
        unix % 60,
        clock.subsec_micros()
    );
    let manifest = &view["manifest"];
    let response = json!({"schemaVersion":"guard.extension-catalog-sync.v2","catalogDigest":manifest["catalogDigest"],
        "accepted":true,"complete":true,"observation":{"schemaVersion":"guard.catalog-observation.v2",
        "nonce":begun["payload"]["idempotencyKey"],"credentialBinding":request["credential_binding"],
        "identity":request["identity"],"catalogDigest":manifest["catalogDigest"],
        "enforcementCatalogDigest":manifest["enforcementCatalogDigest"],"guardVersion":manifest["guardVersion"],
        "controlSchemaVersion":manifest["controlSchemaVersion"],"observedAt":date}});
    request["action"] = json!("completion_accept");
    request["response"] = response.clone();
    for (field, bad) in [
        ("nonce", json!("a".repeat(64))),
        ("credentialBinding", json!("e".repeat(64))),
        ("catalogDigest", json!("f".repeat(64))),
        ("enforcementCatalogDigest", json!("f".repeat(64))),
        ("observedAt", json!("2000-01-01T00:00:00Z")),
        ("observedAt", json!("2099-01-01T00:00:00Z")),
        ("guardVersion", json!("old")),
        ("identity", json!({"ownerUserId":"other"})),
    ] {
        request["response"]["observation"][field] = bad;
        assert!(evaluate(&request).get("error").is_some(), "{field}");
        request["response"] = response.clone();
    }
    request["observation"]["enforcement_catalog_digest"] = json!("e".repeat(64));
    assert!(evaluate(&request).get("error").is_some());
    request["observation"] = json!(observation(home.path()));
    assert!(evaluate(&request).get("error").is_none());
    assert!(
        evaluate(&request).get("error").is_some(),
        "single-use challenge"
    );
    request["action"] = json!("completion_read");
    assert_eq!(evaluate(&request)["payload"], response["observation"]);
    // An overlapping request must keep its own authenticated single-use nonce,
    // even after the first response commits and its challenge is consumed.
    request["action"] = json!("completion_accept");
    request["response"]["observation"]["nonce"] = overlapping["payload"]["idempotencyKey"].clone();
    assert!(evaluate(&request).get("error").is_none());
    assert!(evaluate(&request).get("error").is_some());
    request["action"] = json!("completion_read");
    assert_eq!(
        evaluate(&request)["payload"],
        request["response"]["observation"]
    );
    fs::write(
        home.path()
            .join("native-runtime/cloud-catalog/completion.json"),
        b"{}",
    )
    .unwrap();
    assert!(
        evaluate(&request).get("error").is_some(),
        "CAS/cache cannot forge completion"
    );
}
