use super::wire_v1::evaluate;
use serde_json::{json, Value};

const DELIVERY_LIMITS: &str = include_str!("../../../../contracts/catalog-delivery/limits.json");
const CLOUD_V1_LIMITS: &str = include_str!("../../../../contracts/managed-controls/v1/limits.json");
const URL: &str = "https://cloud.example/api/guard/runtime/sessions/sync";
const FALLBACK: &str = "2026-10-09T12:00:00Z";
const UPLOAD_PATH: &str = "/api/guard/runtime/extension-catalog/sync";
const OVER_LIMIT: &str = "catalog_upload_exceeds_cloud_limit";

fn digest() -> String {
    "a".repeat(64)
}

fn session() -> Value {
    json!({"extensionCatalogDigest": digest(), "updatedAt": "2026-10-09T00:00:00Z"})
}

fn signal(known: bool) -> Value {
    json!({
        "catalogDigest": digest(), "catalogKnown": known, "uploadRequired": !known,
        "uploadPath": UPLOAD_PATH,
    })
}

fn built(catalog_bytes: u64, body_bytes: u64) -> Value {
    json!({
        "outcome": "built", "catalog_digest": digest(),
        "catalog_bytes": catalog_bytes, "body_bytes": body_bytes,
    })
}

fn negotiate(session: &Value, handshake: &Value, catalog: &Value, url: &str) -> Value {
    let answer = evaluate(&json!({
        "action": "v1_handshake", "session": session, "handshake": handshake,
        "runtime_sync_url": url, "fallback_generated_at": FALLBACK, "catalog": catalog,
    }));
    assert_eq!(answer["schema"], "guard-cloud-catalog-result.v2");
    answer["payload"].clone()
}

fn upload(catalog: &Value) -> Value {
    negotiate(&session(), &signal(false), catalog, URL)
}

fn summary(payload: &Value) -> &Value {
    assert_eq!(payload["decision"], "done", "{payload}");
    &payload["summary"]
}

fn downgraded(reason: &str) -> Value {
    json!({
        "managedControlsCapabilities": [],
        "extension_catalog_sync_status": "downgraded",
        "extension_catalog_sync_reason": reason,
    })
}

fn refusal(kind: &str, message: &str) -> Value {
    json!({"v1_error": kind, "message": message})
}

#[test]
fn byte_budgets_match_the_published_contracts() {
    let delivery: Value = serde_json::from_str(DELIVERY_LIMITS).unwrap();
    let cloud: Value = serde_json::from_str(CLOUD_V1_LIMITS).unwrap();
    assert_eq!(cloud["max_catalog_payload_bytes"], 1_000_000);
    assert_eq!(delivery["cloud_v1_catalog_sync_max_body_bytes"], 1_016_384);
    // The same numbers, observed through the verdict's own boundaries.
    for (catalog, body, sent) in [
        (999_999, 1_016_383, true),
        (1_000_000, 1_016_384, true),
        (1_000_001, 1_016_384, false),
        (1_000_000, 1_016_385, false),
    ] {
        let payload = upload(&built(catalog, body));
        let status = summary(&payload)["extension_catalog_sync_status"].clone();
        assert_eq!(
            status == "uploaded",
            sent,
            "catalog {catalog} body {body}: {payload}"
        );
        if !sent {
            assert_eq!(payload["summary"], downgraded(OVER_LIMIT));
            assert_eq!(payload["upload_url"], Value::Null);
        }
    }
}

#[test]
fn no_catalog_posture_reports_nothing() {
    for catalog in [Value::Null, built(10, 100), json!({"outcome": "limit"})] {
        let payload = negotiate(&json!({}), &Value::Null, &catalog, URL);
        assert_eq!(
            payload,
            json!({"decision": "done", "summary": {}, "upload_url": null})
        );
    }
}

#[test]
fn view_digest_without_a_legacy_digest_is_unsupported() {
    let unsupported = json!({
        "managedControlsCapabilities": [],
        "extension_catalog_sync_status": "unsupported",
        "extension_catalog_sync_reason": "complete_catalog_exceeds_cloud_v1_limits",
    });
    for session in [
        json!({"extensionCatalogViewDigest": digest(), "managedControlsCapabilities": ["x"]}),
        json!({"extensionCatalogViewDigest": null}),
        json!({"extensionCatalogViewDigest": digest(), "extensionCatalogDigest": 7}),
    ] {
        let payload = negotiate(&session, &signal(false), &Value::Null, URL);
        assert_eq!(summary(&payload), &unsupported);
        assert_eq!(payload["upload_url"], Value::Null);
    }
}

#[test]
fn posture_without_a_digest_probes_for_the_cloud_limit() {
    let session = json!({"managedControlsCapabilities": []});
    let asked = negotiate(&session, &Value::Null, &Value::Null, URL);
    assert_eq!(
        asked,
        json!({
            "decision": "need_catalog", "purpose": "probe",
            "generated_at": FALLBACK, "idempotency_key": null,
        })
    );
    let limited = negotiate(&session, &Value::Null, &json!({"outcome": "limit"}), URL);
    assert_eq!(summary(&limited), &downgraded(OVER_LIMIT));
    // Any other outcome reports nothing, as a failed build always has.
    for other in [
        json!({"outcome": "unavailable"}),
        json!({"outcome": "failed"}),
        json!({"outcome": "built"}),
        built(10, 100),
    ] {
        let payload = negotiate(&session, &Value::Null, &other, URL);
        assert_eq!(summary(&payload), &json!({}), "{other}");
    }
}

#[test]
fn cloud_without_a_signal_downgrades_without_building() {
    let payload = negotiate(&session(), &Value::Null, &Value::Null, URL);
    assert_eq!(
        summary(&payload),
        &downgraded("catalog_handshake_unavailable")
    );
}

#[test]
fn malformed_or_unbound_signals_are_refused() {
    let mut surplus = signal(false);
    surplus["unexpected"] = json!(true);
    let mut missing = signal(false);
    missing.as_object_mut().unwrap().remove("uploadPath");
    let wrong_path = json!({
        "catalogDigest": digest(), "catalogKnown": false, "uploadRequired": true,
        "uploadPath": "/attacker/upload",
    });
    let neither = json!({
        "catalogDigest": digest(), "catalogKnown": false, "uploadRequired": false,
        "uploadPath": UPLOAD_PATH,
    });
    let both = json!({
        "catalogDigest": digest(), "catalogKnown": true, "uploadRequired": true,
        "uploadPath": UPLOAD_PATH,
    });
    let other_digest = json!({
        "catalogDigest": "b".repeat(64), "catalogKnown": true, "uploadRequired": false,
        "uploadPath": UPLOAD_PATH,
    });
    let spelled = json!({
        "catalogDigest": digest(), "catalogKnown": "false", "uploadRequired": true,
        "uploadPath": UPLOAD_PATH,
    });
    for handshake in [
        surplus,
        missing,
        wrong_path,
        neither,
        both,
        other_digest,
        spelled,
        json!("known"),
        json!([]),
    ] {
        let payload = negotiate(&session(), &handshake, &Value::Null, URL);
        assert_eq!(
            payload,
            refusal("protocol", "Invalid Extension catalog handshake response"),
            "{handshake}"
        );
    }
}

#[test]
fn a_known_catalog_is_never_asked_for() {
    let payload = negotiate(&session(), &signal(true), &Value::Null, URL);
    assert_eq!(
        payload,
        json!({
            "decision": "done", "upload_url": null,
            "summary": {
                "extension_catalog_sync_status": "already_known",
                "extension_catalog_sync_digest": digest(),
            },
        })
    );
}

#[test]
fn an_unknown_catalog_is_requested_for_the_session_time_or_the_fallback() {
    let expected = |generated_at: &str| {
        json!({
            "decision": "need_catalog", "purpose": "upload", "generated_at": generated_at,
            "idempotency_key": format!("catalog:{}", digest()),
        })
    };
    let payload = negotiate(&session(), &signal(false), &Value::Null, URL);
    assert_eq!(payload, expected("2026-10-09T00:00:00Z"));
    for updated_at in [json!(""), json!(7), Value::Null] {
        let mut session = session();
        session["updatedAt"] = updated_at;
        assert_eq!(
            negotiate(&session, &signal(false), &Value::Null, URL),
            expected(FALLBACK)
        );
    }
    let mut absent = session();
    absent.as_object_mut().unwrap().remove("updatedAt");
    assert_eq!(
        negotiate(&absent, &signal(false), &Value::Null, URL),
        expected(FALLBACK)
    );
}

#[test]
fn builder_limits_and_a_missing_runtime_downgrade_a_requested_upload() {
    let limited = upload(&json!({"outcome": "limit"}));
    assert_eq!(summary(&limited), &downgraded(OVER_LIMIT));
    let unavailable = upload(&json!({"outcome": "unavailable"}));
    assert_eq!(
        summary(&unavailable),
        &downgraded("catalog_runtime_unavailable")
    );
    assert_eq!(unavailable["upload_url"], Value::Null);
    // A build failure that is neither is the adapter's to raise, not a verdict.
    assert_eq!(
        upload(&json!({"outcome": "failed"})),
        refusal("invalid", "Invalid Extension catalog observation")
    );
}

#[test]
fn a_catalog_that_changed_since_the_posture_is_refused() {
    let mut other = built(10, 100);
    other["catalog_digest"] = json!("b".repeat(64));
    let mut unnamed = built(10, 100);
    unnamed.as_object_mut().unwrap().remove("catalog_digest");
    for catalog in [other, unnamed] {
        assert_eq!(
            upload(&catalog),
            refusal(
                "protocol",
                "Extension catalog changed during runtime synchronization"
            )
        );
    }
}

#[test]
fn malformed_observations_are_invalid_requests() {
    for catalog in [
        json!({"outcome": "surprise"}),
        json!({"outcome": "built", "catalog_digest": digest(), "body_bytes": 1}),
        json!({"outcome": "built", "catalog_digest": digest(), "catalog_bytes": -1, "body_bytes": 1}),
        json!({"outcome": "built", "catalog_digest": digest(), "catalog_bytes": "1", "body_bytes": 1}),
        json!("built"),
    ] {
        assert_eq!(
            upload(&catalog),
            refusal("invalid", "Invalid Extension catalog observation"),
            "{catalog}"
        );
    }
    let request = json!({"action": "v1_handshake", "session": session(), "handshake": null});
    assert_eq!(
        evaluate(&request)["payload"],
        refusal("invalid", "Invalid Extension catalog handshake request")
    );
}

/// Pinned from the previous Python normalization: scheme, authority and query
/// of the configured session URL survive, the fragment and path do not.
#[test]
fn the_upload_url_keeps_scheme_authority_and_query_only() {
    let sync = "api/guard/runtime/extension-catalog/sync";
    for (configured, expected) in [
        (
            "https://hol.org/api/guard/runtime/sessions/sync",
            format!("https://hol.org/{sync}"),
        ),
        (
            "https://hol.org/api/guard/runtime/sessions/sync?tenant=guard#frag",
            format!("https://hol.org/{sync}?tenant=guard"),
        ),
        (
            "http://127.0.0.1:8080/x?y=1",
            format!("http://127.0.0.1:8080/{sync}?y=1"),
        ),
        ("HTTPS://Hol.Org/a", format!("https://Hol.Org/{sync}")),
        (
            "https://u:p@hol.org/a?q=1",
            format!("https://u:p@hol.org/{sync}?q=1"),
        ),
        ("https://hol.org?x=1", format!("https://hol.org/{sync}?x=1")),
        ("  https://hol.org/a", format!("https://hol.org/{sync}")),
        (
            "https://ho\tl.org/\na?q=1\r",
            format!("https://hol.org/{sync}?q=1"),
        ),
        ("\u{1}https://hol.org/a", format!("https://hol.org/{sync}")),
        ("https://[::1]:8080/a", format!("https://[::1]:8080/{sync}")),
        (
            "https://[fe80::1%25en0]:8080/a",
            format!("https://[fe80::1%25en0]:8080/{sync}"),
        ),
        (
            "https://[v1.fe80::a]/a",
            format!("https://[v1.fe80::a]/{sync}"),
        ),
        ("https://hol.org/a?", format!("https://hol.org/{sync}")),
        (
            "https://hol.org/a?b?c#d",
            format!("https://hol.org/{sync}?b?c"),
        ),
        ("https://hol.org#f?q", format!("https://hol.org/{sync}")),
        (
            "ht+tp-1.x://hol.org/a",
            format!("ht+tp-1.x://hol.org/{sync}"),
        ),
        (
            "https://b\u{fc}cher.example/a",
            format!("https://b\u{fc}cher.example/{sync}"),
        ),
    ] {
        let payload = negotiate(&session(), &signal(false), &built(10, 100), configured);
        assert_eq!(payload["upload_url"], expected, "{configured:?}");
        assert_eq!(
            payload["summary"],
            json!({
                "extension_catalog_sync_status": "uploaded",
                "extension_catalog_sync_digest": digest(),
            })
        );
    }
}

/// The previous normalization turned each of these into a relative or
/// authority-less URL that no request could use; they are refused instead.
#[test]
fn an_upload_url_without_a_scheme_and_authority_is_refused() {
    for configured in [
        "",
        "hol.org/a",
        "//hol.org/a",
        "localhost:8080/a",
        "file:///a",
        "http:/a",
        "https:?q=1",
        "1http://hol.org/a",
        "ht_tp://hol.org/a",
        "https://[::1/a",
        "https://::1]/a",
        "https://[hol.org]/a",
        "https://[1.2.3.4]/a",
        "https://[fe80::1%]/a",
        "https://[fe80::1%a%b]/a",
        "https://[v.a]/a",
        "https://[vg.a]/a",
        "https://[v1.]/a",
    ] {
        let payload = negotiate(&session(), &signal(false), &built(10, 100), configured);
        assert_eq!(
            payload,
            refusal("protocol", "Invalid Extension catalog upload URL"),
            "{configured:?}"
        );
    }
    let mut request = json!({
        "action": "v1_handshake", "session": session(), "handshake": signal(false),
        "fallback_generated_at": FALLBACK, "catalog": built(10, 100),
    });
    assert_eq!(
        evaluate(&request)["payload"],
        refusal("invalid", "Invalid Extension catalog handshake request")
    );
    request["fallback_generated_at"] = json!(7);
    assert_eq!(
        evaluate(&request)["payload"],
        refusal("invalid", "Invalid Extension catalog handshake request")
    );
}

fn acknowledgement() -> Value {
    json!({
        "schemaVersion": "guard.extension-catalog-sync.v1", "accepted": true,
        "catalogDigest": digest(), "alreadyKnown": false, "deviceCount": 1,
        "firstSeenAt": "2026-08-25T00:00:00Z", "lastSeenAt": "2026-08-25T00:00:00Z",
    })
}

fn acknowledge(response: &Value) -> Value {
    evaluate(&json!({
        "action": "v1_sync_ack", "response": response, "expected_digest": digest(),
    }))["payload"]
        .clone()
}

#[test]
fn an_acknowledgement_must_bind_the_uploaded_digest() {
    assert_eq!(acknowledge(&acknowledgement()), json!({"accepted": true}));
    let mut known = acknowledgement();
    known["alreadyKnown"] = json!(true);
    known["deviceCount"] = json!(4_000_000_000_u64);
    assert_eq!(acknowledge(&known), json!({"accepted": true}));
    let broken = |field: &str, value: Value| {
        let mut response = acknowledgement();
        response[field] = value;
        response
    };
    let mut surplus = acknowledgement();
    surplus["unexpected"] = json!(1);
    let mut missing = acknowledgement();
    missing.as_object_mut().unwrap().remove("lastSeenAt");
    for response in [
        broken("catalogDigest", json!("b".repeat(64))),
        broken("schemaVersion", json!("guard.extension-catalog-sync.v2")),
        broken("accepted", json!(false)),
        broken("accepted", json!("true")),
        broken("alreadyKnown", json!("false")),
        broken("alreadyKnown", Value::Null),
        broken("deviceCount", json!(0)),
        broken("deviceCount", json!(-1)),
        broken("deviceCount", json!(true)),
        broken("deviceCount", json!(1.0)),
        broken("deviceCount", json!("1")),
        broken("firstSeenAt", json!("")),
        broken("firstSeenAt", json!(7)),
        broken("lastSeenAt", json!("")),
        broken("lastSeenAt", Value::Null),
        surplus,
        missing,
        json!([]),
        Value::Null,
    ] {
        assert_eq!(
            acknowledge(&response),
            refusal("protocol", "Invalid Extension catalog sync response"),
            "{response}"
        );
    }
    let unbound = evaluate(&json!({"action": "v1_sync_ack", "response": acknowledgement()}));
    assert_eq!(
        unbound["payload"],
        refusal("invalid", "Invalid Extension catalog sync request")
    );
}
