use serde_json::{json, Value};

use super::evaluate;

const KEY: [u8; 32] = {
    let mut key = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        key[index] = index as u8;
        index += 1;
    }
    key
};

fn digest(c: char) -> String {
    c.to_string().repeat(64)
}

fn reference() -> Value {
    json!({"sha256": digest('a'), "length": 10, "expanded_length": 10, "kind": "data"})
}

fn activation() -> Value {
    json!({
        "schema": "guard.command-pack-activation.v2", "revision": 1, "previous_digest": null,
        "program_digest": digest('1'), "catalog_digest": digest('2'), "trust_digest": digest('3'),
        "engine": digest('4'), "source_sha": "5".repeat(40), "publication_id": "0.0",
        "root_digest": digest('a'), "authority_epoch": 1, "revocation_epoch": 0,
        "issued_at": null, "expires_at": null, "selection": reference(), "selected_count": 1,
        "registry": reference(), "registry_count": 1, "executables": null,
        "executable_count": 0, "distribution": reference(), "authority_profile": "installed",
    })
}

fn baseline() -> Value {
    json!({
        "schema": "guard.command-pack-legacy-baseline.v1", "revision": 0,
        "program_digest": digest('1'), "catalog_digest": digest('2'), "trust_digest": digest('3'),
    })
}

fn link() -> Value {
    json!({
        "control_revision": 7, "snapshot_digest": digest('6'), "catalog_digest": digest('2'),
        "pack_record_digest": digest('7'), "admitted_at": 1500,
        "lifecycle_before": {"a": 1}, "lifecycle_after": {"a": 2},
    })
}

fn expected() -> Value {
    json!({
        "control_revision": 7, "snapshot_digest": digest('6'), "catalog_digest": digest('2'),
        "pack_record_digest": digest('7'),
    })
}

fn seal(purpose: &str, payload: Value) -> Result<Value, String> {
    evaluate(
        &json!({"operation": "seal", "purpose": purpose, "payload": payload}),
        &KEY,
    )
}

fn verify(purpose: &str, sealed: &Value, extra: Value) -> Result<Value, String> {
    let mut input = json!({
        "operation": "verify", "purpose": purpose,
        "record": sealed["record"], "digest": sealed["digest"], "mac": sealed["mac"],
    });
    for (name, value) in extra.as_object().unwrap() {
        input[name] = value.clone();
    }
    evaluate(&input, &KEY)
}

/// The answer a refused record travels as. A record this reader will not accept
/// is a decision about the record, so it reaches the caller on stdout like any
/// other answer rather than as a transport error.
fn refused(reason: &str) -> Result<Value, String> {
    Ok(json!({"fault": "refused", "reason": reason}))
}

/// Seal `record` as it is, bypassing the writer's validation, so the reader
/// alone has to refuse it.
fn forged(purpose: &str, record: Value) -> Value {
    use crate::extension_control_authority_op::records::authenticated_record;
    let (record, digest, mac) =
        authenticated_record(record.as_object().unwrap(), &KEY, purpose).unwrap();
    json!({"record": record, "digest": digest, "mac": mac})
}

#[test]
fn sealed_records_match_the_python_writer_byte_for_byte() {
    // The digests and MACs Python's authenticated_record produced for the
    // same payloads and key.
    for (purpose, payload, digest, mac) in [
        (
            "activation",
            activation(),
            "bf44395da67b0082e416bb85ceb0f7bc8a9e4f4257d3b2f860b68e499934b0f2",
            "642fc7a77d2338e8bed4b3134ee0fef4c9889536c6ff21084a35647daf3ab459",
        ),
        (
            "baseline",
            baseline(),
            "3ab4d7c74616b8ea3cb1373ae6186b1898e2c9ce6aab3a9bc45d873771a5a8d6",
            "16159b45ea7b9e1f8cbad8fa80abcb741351b4a3185a7bb0ec8969b8c02161fb",
        ),
        (
            "link",
            link(),
            "5438d78f40bc09294264a1dbe6ad8073f0b6eb82750ace9f140d2649c22f5673",
            "ee65af85185e7fac4d7d2ee2724fcfd6fab13579b650cd5b8ecf4707177ce186",
        ),
    ] {
        let sealed = seal(purpose, payload).unwrap();
        assert_eq!(sealed["digest"], json!(digest), "{purpose}");
        assert_eq!(sealed["mac"], json!(mac), "{purpose}");
    }
}

#[test]
fn sealed_records_verify_through_their_readers() {
    let sealed = seal("activation", activation()).unwrap();
    let value = verify("activation", &sealed, json!({})).unwrap();
    assert_eq!(value["value"]["revision"], json!(1));
    let sealed = seal("baseline", baseline()).unwrap();
    let value = verify("baseline", &sealed, json!({"revision": 0})).unwrap();
    assert_eq!(value["value"]["schema"], baseline()["schema"]);
    let sealed = seal("link", link()).unwrap();
    let value = verify("link", &sealed, json!({"expected": expected()})).unwrap();
    assert_eq!(value["value"]["admitted_at"], json!(1500));
}

#[test]
fn records_that_do_not_authenticate_are_tampered() {
    let sealed = seal("activation", activation()).unwrap();
    let mut wrong_mac = sealed.clone();
    wrong_mac["mac"] = json!(digest('0'));
    let respaced = json!({
        "record": serde_json::to_string_pretty(
            &serde_json::from_str::<Value>(sealed["record"].as_str().unwrap()).unwrap()
        ).unwrap(),
        "digest": sealed["digest"], "mac": sealed["mac"],
    });
    let duplicated = json!({
        "record": sealed["record"].as_str().unwrap().replacen("{", "{\"revision\":9,", 1),
        "digest": sealed["digest"], "mac": sealed["mac"],
    });
    for (case, purpose) in [
        (wrong_mac, "activation"),
        (respaced, "activation"),
        (duplicated, "activation"),
        (sealed, "baseline"),
    ] {
        let result = verify(purpose, &case, json!({"revision": 0})).unwrap();
        assert_eq!(result["fault"], json!("tampered"), "{result}");
    }
}

#[test]
fn authenticated_records_outside_the_schema_are_refused_by_name() {
    let with = |name: &str, value: Value| {
        let mut record = activation();
        record[name] = value;
        record
    };
    for (record, reason) in [
        (
            with("authority_profile", json!("cloud")),
            "activation authority profile invalid",
        ),
        (
            with("schema", json!("guard.command-pack-activation.v3")),
            "activation record schema invalid",
        ),
        (
            with("engine", json!("E".repeat(64))),
            "activation digest invalid",
        ),
        (
            with("publication_id", json!("1.2")),
            "activation installed authority invalid",
        ),
        (
            with("issued_at", json!(5)),
            "installed activation cannot claim remote freshness",
        ),
        (
            with("source_sha", json!("5".repeat(39))),
            "activation source identity invalid",
        ),
        (
            with("revision", json!(0)),
            "activation epoch or revision invalid",
        ),
        (
            with("revision", json!(1.0)),
            "activation epoch or revision invalid",
        ),
        (
            with("previous_digest", json!("x")),
            "activation predecessor invalid",
        ),
        (
            with("selected_count", json!(0)),
            "activation metadata count invalid",
        ),
        (
            with("executables", reference()),
            "activation metadata reference missing",
        ),
        (
            with("distribution", json!({"sha256": digest('a')})),
            "delivery index object reference invalid",
        ),
    ] {
        let sealed = forged("command-pack-activation.v1", record.clone());
        assert_eq!(verify("activation", &sealed, json!({})), refused(reason));
        assert_eq!(seal("activation", record), refused(reason));
    }
    let mut remote = activation();
    remote["authority_profile"] = json!("remote");
    remote["publication_id"] = json!("1.2");
    remote["issued_at"] = json!(10);
    remote["expires_at"] = json!(10);
    assert_eq!(
        seal("activation", remote),
        refused("activation validity interval invalid")
    );
}

#[test]
fn located_references_name_the_asset_they_come_from() {
    let tag = format!("extension-data-{}-1.2-000001", "5".repeat(40));
    let member = format!("object-{}.json", digest('a'));
    for (location, accepted) in [
        (json!({"tag": tag, "asset": member}), true),
        (
            json!({"tag": tag, "asset": "objects-000001.zip", "member": member}),
            true,
        ),
        (
            json!({"tag": tag, "asset": "packs-000001.zip", "member": member}),
            false,
        ),
        (json!({"tag": tag, "asset": "object-x.json"}), false),
        (json!({"tag": "release", "asset": member}), false),
    ] {
        let mut record = activation();
        record["distribution"]["location"] = location;
        assert_eq!(
            seal("activation", record).unwrap()["fault"].is_null(),
            accepted
        );
    }
}

#[test]
fn baselines_and_links_bind_only_what_they_name() {
    let sealed = seal("baseline", baseline()).unwrap();
    assert_eq!(
        verify("baseline", &sealed, json!({"revision": 1})),
        refused("legacy activation baseline invalid")
    );
    let mut record = baseline();
    record["trust_digest"] = json!("t");
    let sealed = forged("command-pack-legacy-baseline.v1", record);
    assert_eq!(
        verify("baseline", &sealed, json!({"revision": 0})),
        refused("legacy activation baseline digest invalid")
    );
    let sealed = seal("link", link()).unwrap();
    let mut other = expected();
    other["control_revision"] = json!(8);
    for expected in [other, json!({})] {
        assert_eq!(
            verify("link", &sealed, json!({"expected": expected})),
            refused("native_command_pack_transition_mismatch")
        );
    }
    let mut half = link();
    half.as_object_mut().unwrap().remove("lifecycle_after");
    assert_eq!(
        seal("link", half),
        refused("native_command_pack_link_invalid")
    );
}

#[test]
fn only_an_operation_this_evaluator_does_not_implement_is_an_error() {
    // A refusal decides something about the record and reaches the caller as an
    // answer; an unimplemented operation decides nothing, so it stays an error.
    assert_eq!(
        evaluate(
            &json!({"operation": "rewrite", "purpose": "activation", "payload": activation()}),
            &KEY
        ),
        Err("pack_lifecycle_record_operation_invalid".into())
    );
    let mut record = activation();
    record["revision"] = json!(0);
    let answer = seal("activation", record).unwrap();
    assert_eq!(answer["fault"], json!("refused"));
    assert_eq!(
        answer["reason"],
        json!("activation epoch or revision invalid")
    );
}
