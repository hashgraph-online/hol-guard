use serde_json::{json, Value};

use super::parse;

const ACTIVE: &str = "0123456789abcdef0123456789abcdef";
const PENDING: &str = "fedcba9876543210fedcba9876543210";

fn key(generation: &str) -> Value {
    json!({
        "generation": generation,
        "keyId": "key-id",
        "publicKeySpki": "MFkw",
        "protectionLevel": "os-protected",
        "createdAt": "2026-07-17T00:00:00+00:00",
    })
}

fn active() -> Value {
    json!({
        "schemaVersion": "hol-guard-device-key.v1",
        "state": "active",
        "active": key(ACTIVE),
        "pendingGeneration": null,
        "previous": null,
        "updatedAt": "2026-07-17T00:00:00+00:00",
    })
}

fn parsed(value: &Value) -> Option<Value> {
    parse(&serde_json::to_vec(value).unwrap())
}

fn with(mut value: Value, pointer: &str, replacement: Value) -> Value {
    *value.pointer_mut(pointer).unwrap() = replacement;
    value
}

#[test]
fn metadata_the_lifecycle_wrote_reads_back_unchanged() {
    let rotating = with(
        with(active(), "/state", json!("rotation_pending")),
        "/pendingGeneration",
        json!(PENDING),
    );
    let revoked = json!({
        "schemaVersion": "hol-guard-device-key.v1",
        "state": "revoked",
        "active": null,
        "pendingGeneration": null,
        "previous": key(PENDING),
        "updatedAt": "2026-07-17T00:00:00+00:00",
    });
    for metadata in [active(), rotating, revoked] {
        assert_eq!(parsed(&metadata), Some(metadata.clone()), "{metadata}");
    }
}

#[test]
fn fields_the_lifecycle_never_reads_are_dropped() {
    let mut extra = active();
    extra["note"] = json!("ignored");
    extra["active"]["label"] = json!("ignored");
    let mut missing = active();
    let fields = missing.as_object_mut().unwrap();
    fields.remove("pendingGeneration");
    fields.remove("previous");

    assert_eq!(parsed(&extra), Some(active()));
    assert_eq!(parsed(&missing), Some(active()));
}

#[test]
fn malformed_metadata_is_refused() {
    let long_key = "A".repeat(1025);
    for metadata in [
        json!([active()]),
        with(active(), "/schemaVersion", json!("hol-guard-device-key.v2")),
        with(active(), "/state", json!("unknown")),
        with(active(), "/state", json!(["active"])),
        with(active(), "/updatedAt", json!("")),
        with(active(), "/updatedAt", json!(1)),
        with(active(), "/active", json!("key")),
        with(active(), "/active/generation", json!(ACTIVE.to_uppercase())),
        with(active(), "/active/generation", json!(&ACTIVE[1..])),
        with(active(), "/active/keyId", json!("")),
        with(active(), "/active/publicKeySpki", json!(long_key)),
        with(active(), "/active/protectionLevel", json!("software")),
        with(active(), "/active/protectionLevel", json!(["os-protected"])),
        with(active(), "/active/createdAt", Value::Null),
        with(active(), "/previous", json!({"generation": PENDING})),
    ] {
        assert_eq!(parsed(&metadata), None, "{metadata}");
    }
    assert_eq!(parse(b"{"), None);
    assert_eq!(parse(b"\xff"), None);
}

#[test]
fn a_public_key_is_bounded_in_characters_not_bytes() {
    let wide = "\u{e9}".repeat(1024);
    let metadata = with(active(), "/active/publicKeySpki", json!(wide));

    assert_eq!(parsed(&metadata), Some(metadata.clone()));
}

#[test]
fn the_state_must_agree_with_its_generations() {
    for metadata in [
        with(active(), "/active", Value::Null),
        with(active(), "/pendingGeneration", json!(PENDING)),
        with(active(), "/state", json!("pending")),
        with(active(), "/state", json!("rotation_pending")),
        with(
            with(active(), "/state", json!("pending")),
            "/pendingGeneration",
            json!("not-hex"),
        ),
    ] {
        assert_eq!(parsed(&metadata), None, "{metadata}");
    }
    let pending = with(
        with(
            with(active(), "/state", json!("pending")),
            "/active",
            Value::Null,
        ),
        "/pendingGeneration",
        json!(PENDING),
    );
    assert_eq!(parsed(&pending), Some(pending.clone()));
}
