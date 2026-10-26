use super::*;
use crate::pack_lifecycle::evaluate as dispatch;
use serde_json::json;

pub(super) const SOURCE: &str = "ffa0eaa6ac9a1ca8daaa18cc587937dbd501cfd5";

fn root() -> Value {
    let reference =
        json!({"sha256": "2".repeat(64), "length": 100, "expanded_length": 100, "kind": "data"});
    let mut located = reference.clone();
    located["location"] = json!({
        "tag": format!("extension-data-{SOURCE}-0.0-000000"),
        "asset": format!("object-{}.json", "2".repeat(64)),
    });
    json!({
        "schema": "guard.extension-distribution.v2",
        "source_sha": SOURCE,
        "engine": "1".repeat(64),
        "authority_epoch": 1,
        "publication_id": "12.1",
        "issued_at": 1000,
        "expires_at": 2000,
        "directory": {"count": 1, "index": located, "claims": {"count": 0, "index": null}},
        "policy": {
            "root": {
                "schema": "guard.command-pack-release.v1",
                "engine": "1".repeat(64),
                "extensions": 1,
                "index": reference,
            },
            "transport": located,
            "defaults": {"count": 0, "index": null},
            "revocations": {"epoch": 0, "count": 0, "index": null},
        },
        "claim_provenance": "resolved",
        "legacy": {"status": "unsupported-oversize", "code": "program-bytes"},
    })
}

fn check_text(data: &str, now: u64) -> Result<Value, String> {
    dispatch(&json!({
        "kind": "distribution", "operation": "root", "data": data, "source": SOURCE, "now": now,
    }))
}

fn check(value: &Value, now: u64) -> Result<Value, String> {
    check_text(&value.to_string(), now)
}

fn expect(value: Value, code: &str, why: &str) {
    assert_eq!(check(&value, 1500), Err(code.into()), "{why}");
}

fn with(pointer: &str, to: Value) -> Value {
    let mut value = root();
    *value.pointer_mut(pointer).unwrap() = to;
    value
}

fn without(pointer: &str, key: &str) -> Value {
    let mut value = root();
    value
        .pointer_mut(pointer)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(key);
    value
}

#[test]
fn a_complete_current_root_reports_its_expiry() {
    assert_eq!(check(&root(), 1500), Ok(json!({"expires_at": 2000})));
}

#[test]
fn identity_epoch_and_publication_mistakes_have_their_own_reasons() {
    let identity = "distribution_identity_invalid";
    let cases = [
        ("/authority_epoch", json!(0), "distribution_epoch_invalid"),
        (
            "/authority_epoch",
            json!(true),
            "distribution_epoch_invalid",
        ),
        ("/source_sha", json!("0".repeat(40)), identity),
        ("/engine", json!("invalid"), identity),
        (
            "/schema",
            json!("guard.extension-distribution.v1"),
            identity,
        ),
        (
            "/publication_id",
            json!("12"),
            "distribution_publication_invalid",
        ),
        (
            "/publication_id",
            json!("1.2.3"),
            "distribution_publication_invalid",
        ),
        (
            "/publication_id",
            json!("1".repeat(21) + ".1"),
            "distribution_publication_invalid",
        ),
        (
            "/claim_provenance",
            json!("pending"),
            "distribution_preparation_incomplete",
        ),
    ];
    for (pointer, to, code) in cases {
        expect(with(pointer, to), code, pointer);
    }
    let mut extra = root();
    extra["extra"] = json!(1);
    expect(extra, identity, "extra field");
    expect(without("", "legacy"), identity, "missing field");
}

#[test]
fn the_validity_window_is_bounded_and_integer_only() {
    let week = 7 * 24 * 60 * 60;
    let invalid = "distribution_validity_invalid";
    let cases = [
        ("/expires_at", json!(1499), "distribution_expired"),
        ("/issued_at", json!(1801), invalid),
        ("/expires_at", json!(1000 + week + 1), invalid),
        ("/expires_at", json!(1000), invalid),
        ("/issued_at", json!(true), invalid),
        ("/expires_at", json!(2000.0), invalid),
    ];
    for (pointer, to, code) in cases {
        expect(with(pointer, to), code, pointer);
    }
    assert!(check(&with("/expires_at", json!(1000 + week)), 1500).is_ok());
    assert!(check(&with("/issued_at", json!(1800)), 1500).is_ok());
    for now in [
        json!(-1),
        json!(1.5),
        json!("1500"),
        json!(null),
        json!(true),
    ] {
        let request = json!({
            "kind": "distribution", "operation": "root", "data": root().to_string(),
            "source": SOURCE, "now": now,
        });
        assert_eq!(dispatch(&request), Err(invalid.into()), "{now}");
    }
}

#[test]
fn a_malformed_root_is_reported_before_it_is_called_expired() {
    let mut value = root();
    value["claim_provenance"] = json!("pending");
    let code = Err("distribution_preparation_incomplete".into());
    assert_eq!(check(&value, 5000), code);
    assert_eq!(check(&root(), 2000), Err("distribution_expired".into()));
    assert_eq!(check(&root(), 1999), Ok(json!({"expires_at": 2000})));
}

#[test]
fn compatibility_status_is_exact() {
    let available = json!({
        "status": "available", "manifest_sha256": "3".repeat(64),
        "archive_sha256": "4".repeat(64), "tag": format!("extension-artifacts-{SOURCE}"),
    });
    assert!(check(&with("/legacy", available.clone()), 1500).is_ok());
    let mut other = available.clone();
    other["tag"] = json!("extension-artifacts-other");
    let mut short = available;
    short["archive_sha256"] = json!("4");
    let artifact = "distribution_legacy_artifact_invalid";
    expect(with("/legacy", other), artifact, "tag");
    expect(with("/legacy", short), artifact, "digest");
    let preparation = "distribution_preparation_incomplete";
    expect(
        with("/legacy", json!({"status": "x"})),
        preparation,
        "status",
    );
    expect(
        with("/legacy", json!("available")),
        "distribution_legacy_status_invalid",
        "type",
    );
    let oversize = "distribution_legacy_oversize_invalid";
    expect(
        with("/legacy/code", json!("unreviewed-error")),
        oversize,
        "code",
    );
}

#[test]
fn directory_and_policy_must_describe_the_same_release() {
    let references = "distribution_references_incomplete";
    let differ = "distribution_identities_differ";
    expect(
        with("/directory", json!({"count": 2, "index": null})),
        references,
        "directory",
    );
    expect(without("/policy", "transport"), references, "policy");
    expect(
        with("/policy/root/engine", json!("5".repeat(64))),
        differ,
        "engine",
    );
    expect(
        with("/policy/root/schema", json!("other")),
        differ,
        "schema",
    );
    expect(
        with("/policy/root/extensions", json!(2)),
        differ,
        "extensions",
    );
    expect(with("/directory/count", json!(0)), differ, "count");
}

#[test]
fn index_references_and_locations_are_exact() {
    let index = "distribution_index_reference_invalid";
    let located = root()["directory"]["index"].clone();
    let mut member = located["location"].clone();
    member["member"] = json!("object-x.json");
    let cases = [
        ("/directory/index/length", json!(65537), index),
        ("/directory/index/expanded_length", json!(99), index),
        ("/policy/transport/kind", json!("zip"), index),
        ("/policy/root/index", located, index),
        (
            "/directory/index/location/tag",
            json!("bad"),
            "distribution_location_invalid",
        ),
        (
            "/policy/transport/location/asset",
            json!("object-x.json"),
            "distribution_location_identity_invalid",
        ),
        (
            "/directory/index/location",
            member,
            "distribution_location_container_invalid",
        ),
    ];
    for (pointer, to, code) in cases {
        expect(with(pointer, to), code, pointer);
    }
}

#[test]
fn optional_indexes_must_agree_with_their_counts() {
    let index = root()["directory"]["index"].clone();
    let cases = [
        (
            "/directory/claims/count",
            json!(2),
            "distribution_claim_count_invalid",
        ),
        (
            "/directory/claims",
            json!({"count": 0}),
            "distribution_claim_count_invalid",
        ),
        (
            "/directory/claims/index",
            json!({}),
            "distribution_claim_index_reference",
        ),
        (
            "/directory/claims/count",
            json!(1),
            "distribution_index_reference_invalid",
        ),
        (
            "/policy/defaults/index",
            json!({}),
            "distribution_security_index_reference",
        ),
        (
            "/policy/defaults",
            json!({"count": -1, "index": null}),
            "distribution_security_count_invalid",
        ),
        (
            "/policy/defaults",
            json!({"count": 2, "index": index}),
            "distribution_defaults_exceed",
        ),
        (
            "/policy/revocations/epoch",
            json!(-1),
            "distribution_revocation_epoch_invalid",
        ),
    ];
    for (pointer, to, code) in cases {
        expect(with(pointer, to), code, pointer);
    }
    let missing = without("/policy/revocations", "epoch");
    expect(missing, "distribution_security_count_invalid", "epoch key");
}

#[test]
fn a_populated_root_accepts_every_located_index() {
    let mut value = root();
    let index = value["directory"]["index"].clone();
    value["directory"]["claims"] = json!({"count": 1, "index": index});
    value["policy"]["defaults"] = json!({"count": 1, "index": index});
    value["policy"]["revocations"] = json!({"epoch": 7, "count": 1, "index": index});
    assert_eq!(check(&value, 1500), Ok(json!({"expires_at": 2000})));
    let location = &mut value["directory"]["index"]["location"];
    location["member"] = json!(format!("object-{}.json", "2".repeat(64)));
    location["asset"] = json!("objects-000001.zip");
    assert_eq!(check(&value, 1500), Ok(json!({"expires_at": 2000})));
}

#[test]
fn bytes_that_are_not_strict_json_never_reach_the_shape_checks() {
    let oversize = "x".repeat(64 * 1024 + 1);
    let nested = format!("{}1{}", "[".repeat(40), "]".repeat(40));
    let cases = [
        ("", "distribution_root_too_large"),
        (oversize.as_str(), "distribution_root_too_large"),
        (r#"{"schema":1,"schema":2}"#, "distribution_duplicate_field"),
        (nested.as_str(), "distribution_encoding_invalid"),
        (r#"{"a":1} x"#, "distribution_encoding_invalid"),
        (r#"{"a":NaN}"#, "distribution_encoding_invalid"),
        (r#"{"a":1e999}"#, "distribution_nonfinite_value"),
        ("[]", "distribution_identity_invalid"),
    ];
    for (text, code) in cases {
        assert_eq!(check_text(text, 1500), Err(code.into()), "{code}");
    }
}

#[test]
fn the_request_names_a_full_commit_and_a_known_operation() {
    for source in [json!("abc"), json!("F".repeat(40)), json!(null)] {
        let request = json!({
            "kind": "distribution", "operation": "root", "data": root().to_string(),
            "source": source, "now": 1500,
        });
        assert_eq!(
            dispatch(&request),
            Err("distribution_source_invalid".into()),
            "{source}"
        );
    }
    let request = json!({"kind": "distribution", "operation": "root", "source": SOURCE, "now": 1});
    assert_eq!(
        dispatch(&request),
        Err("distribution_request_invalid".into())
    );
    let request = json!({"kind": "distribution", "operation": "other"});
    assert_eq!(
        dispatch(&request),
        Err("distribution_operation_invalid".into())
    );
}
