use guard_contracts::{
    CommandPackRecordRequestV1, COMMAND_PACK_RECORD_REQUEST_SCHEMA,
    COMMAND_PACK_RECORD_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate_command_pack_record_request;

const KEY: [u8; 32] = [7; 32];

fn baseline() -> Value {
    json!({
        "schema": "guard.command-pack-legacy-baseline.v1", "revision": 0,
        "program_digest": "1".repeat(64), "catalog_digest": "2".repeat(64),
        "trust_digest": "3".repeat(64),
    })
}

/// A baseline sealed by the one-shot's own evaluator, as a store holds it.
fn sealed() -> Value {
    crate::pack_lifecycle::evaluate(&json!({
        "kind": "record", "operation": "seal", "purpose": "baseline",
        "key": hex::encode(KEY), "payload": baseline(),
    }))
    .unwrap()
}

fn verify_request(sealed: &Value) -> Value {
    json!({
        "kind": "record", "operation": "verify", "purpose": "baseline",
        "key": hex::encode(KEY), "record": sealed["record"], "digest": sealed["digest"],
        "mac": sealed["mac"], "revision": 0,
    })
}

fn ask(guard_home: &str, record: Value) -> Value {
    let request = CommandPackRecordRequestV1 {
        schema: COMMAND_PACK_RECORD_REQUEST_SCHEMA.to_owned(),
        request_id: "record-1".to_owned(),
        guard_home: guard_home.to_owned(),
        store_path: format!("{guard_home}/guard.db"),
        record,
    };
    let bytes = evaluate_command_pack_record_request(&request).unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["schema"], json!(COMMAND_PACK_RECORD_RESULT_SCHEMA));
    assert_eq!(result["request_id"], json!("record-1"));
    result
}

#[test]
fn verify_answers_exactly_what_the_one_shot_answers() {
    let sealed = sealed();
    let request = verify_request(&sealed);
    let result = ask("/unused", request.clone());
    assert_eq!(result["status"], json!("ok"));
    assert_eq!(
        result["payload"],
        crate::pack_lifecycle::evaluate(&request).unwrap()
    );
    assert_eq!(result["payload"]["value"]["schema"], baseline()["schema"]);
}

#[test]
fn a_record_that_does_not_authenticate_is_answered_as_tampered() {
    let mut sealed = sealed();
    sealed["mac"] = json!("0".repeat(64));
    let result = ask("/unused", verify_request(&sealed));
    assert_eq!(result["status"], json!("ok"));
    assert_eq!(result["payload"]["fault"], json!("tampered"));
}

#[test]
fn sealing_and_other_kinds_stay_on_the_one_shot() {
    let mut seal = verify_request(&sealed());
    seal["operation"] = json!("seal");
    let result = ask("/unused", seal);
    assert_eq!(result["status"], json!("error"));
    assert_eq!(
        result["code"],
        json!("native_command_pack_record_operation_invalid")
    );
    assert!(result.get("payload").is_none());

    let result = ask("/unused", json!({"kind": "object", "operation": "read"}));
    assert_eq!(
        result["code"],
        json!("native_command_pack_record_kind_invalid")
    );
}

fn security_request(operation: &str, record: &str) -> Value {
    json!({
        "kind": "active-security", "operation": operation,
        "key": hex::encode(KEY), "record": record,
    })
}

#[test]
fn active_security_reads_answer_exactly_what_the_one_shot_answers() {
    let (record, applicable) = crate::active_pack_security::fixture_record("p", &KEY, false);
    for operation in ["scope", "read"] {
        let request = security_request(operation, &record);
        let result = ask("/unused", request.clone());
        assert_eq!(result["status"], json!("ok"));
        assert_eq!(
            result["payload"],
            crate::pack_lifecycle::evaluate(&request).unwrap()
        );
    }
    let scope = ask("/unused", security_request("scope", &record));
    assert_eq!(scope["payload"]["applicable_digest"], json!(applicable));
}

#[test]
fn active_security_refusals_keep_the_one_shots_code() {
    let (record, _) = crate::active_pack_security::fixture_record("p", &KEY, false);
    let mut check = security_request("check", &record);
    check["expected"] = json!("0".repeat(64));
    let result = ask("/unused", check.clone());
    assert_eq!(result["status"], json!("error"));
    assert_eq!(
        json!(result["code"]),
        json!(crate::pack_lifecycle::evaluate(&check).unwrap_err())
    );

    // A record sealed under another key does not authenticate.
    let (foreign, _) = crate::active_pack_security::fixture_record("p", &[8; 32], false);
    let result = ask("/unused", security_request("read", &foreign));
    assert_eq!(result["status"], json!("error"));
    assert!(result["code"]
        .as_str()
        .unwrap()
        .starts_with("active_security_"));
}

#[test]
fn preparing_active_security_stays_on_the_one_shot() {
    let (record, _) = crate::active_pack_security::fixture_record("p", &KEY, false);
    for operation in ["begin", "complete", "active", ""] {
        let result = ask("/unused", security_request(operation, &record));
        assert_eq!(
            result["code"],
            json!("native_command_pack_record_operation_invalid"),
            "{operation}"
        );
    }
}

#[test]
fn another_request_schema_is_refused() {
    let request = CommandPackRecordRequestV1 {
        schema: "guard-command-pack-record-request.v0".to_owned(),
        request_id: String::new(),
        guard_home: "/unused".to_owned(),
        store_path: "/unused/guard.db".to_owned(),
        record: verify_request(&sealed()),
    };
    let result: Value =
        serde_json::from_slice(&evaluate_command_pack_record_request(&request).unwrap()).unwrap();
    assert_eq!(
        result["code"],
        json!("native_command_pack_record_schema_mismatch")
    );
}

#[test]
fn open_reads_only_the_served_homes_pack_cache() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let cache = home.join("native-runtime").join("command-packs");
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let mut open = verify_request(&sealed());
    open["operation"] = json!("open");
    open["purpose"] = json!("activation");

    for directory in [json!(elsewhere.to_str().unwrap()), json!(""), Value::Null] {
        open["directory"] = directory;
        let result = ask(home.to_str().unwrap(), open.clone());
        assert_eq!(
            result["code"],
            json!("native_command_pack_record_directory_invalid")
        );
    }

    // The served cache reaches the evaluator, which answers about the record.
    open["directory"] = json!(cache.to_str().unwrap());
    let result = ask(home.to_str().unwrap(), open);
    assert_eq!(result["status"], json!("ok"));
    assert!(result["payload"].get("fault").is_some());
}
