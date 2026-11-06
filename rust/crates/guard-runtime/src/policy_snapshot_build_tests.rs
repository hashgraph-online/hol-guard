use super::*;
use serde_json::{json, Value};

pub(super) fn request() -> Value {
    json!({
        "schema": SCHEMA, "version": 1, "verifier_key": vec![7u8; 32],
        "generation": 4, "runtime_identity": "a".repeat(64), "rule_digest": "b".repeat(64),
        "mode": "enforce", "issued_at_ms": 100, "expires_at_ms": 1000,
        "scope_contract": {"schema":"guard-native-scope.v1","kind":"guard-home",
            "scope_digest":"c".repeat(64),"workspace_binding":"request-source"},
        "effective_policy": {
            "protection_posture":"protected","security_level":"balanced","default_action":"warn",
            "unknown_publisher_action":"review","changed_hash_action":"require-reapproval",
            "new_network_domain_action":"warn","subprocess_action":"warn","risk_actions":{},
            "harness_risk_actions":{},"harness_actions":{},"publisher_actions":{},"artifact_actions":{},
            "sandbox_analysis":"off","receipt_redaction_level":"full"
        },
        "business_policy": {"schema":"guard.native-business-policy.v1","version":1,
            "defaultAction":"allow","rules":[{"id":"mail.external","action":"block",
            "match":{"schema":"guard.business-policy-match.v1","version":1,
                "services":["google_gmail"],"operations":["mail_send"]}}]}
    })
}

fn build(value: &Value) -> Result<Vec<u8>, String> {
    build_from_reader(serde_json::to_vec(value).unwrap().as_slice())
}

#[test]
fn generated_business_snapshot_is_native_valid_and_key_is_not_output() {
    let value = request();
    let bytes = build(&value).unwrap();
    let snapshot: PolicySnapshotV3 = serde_json::from_slice(&bytes).unwrap();
    validate_v3(
        &snapshot,
        4,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        200,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot.business_policy).unwrap(),
        value["business_policy"]
    );
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(output.get("verifier_key").is_none());
    assert!(output.get("schema").unwrap() != SCHEMA);
    let mut tampered = snapshot;
    tampered.business_policy.as_mut().unwrap().default_action = "block".into();
    assert!(validate_v3(
        &tampered,
        4,
        &"a".repeat(64),
        &"b".repeat(64),
        &[7; 32],
        200
    )
    .is_err());
}

#[test]
fn binding_changes_both_policy_identity_and_mac_without_changing_config() {
    let value = request();
    let business: PolicySnapshotV3 = serde_json::from_slice(&build(&value).unwrap()).unwrap();
    let mut legacy = value;
    legacy.as_object_mut().unwrap().remove("business_policy");
    let legacy: PolicySnapshotV3 = serde_json::from_slice(&build(&legacy).unwrap()).unwrap();
    assert_eq!(business.config_digest, legacy.config_digest);
    assert_ne!(business.policy_digest, legacy.policy_digest);
    assert_ne!(business.integrity.mac, legacy.integrity.mac);
}

#[test]
fn compiled_complete_source_survives_build_and_content_inspection() {
    use guard_policy_snapshot::business_policy_document::compile_business_document;
    let source = json!({
        "apiVersion":"guard.hashgraphonline.com/v1alpha1","kind":"GuardPolicy",
        "metadata":{"id":"policy.business","name":"Business","revision":1},
        "spec":{"defaults":{"mode":"enforce","defaultAction":"block"},
            "rules":[{"id":"rule.send","enabled":true,"effect":"review",
                "match":{"business":{"schema":"guard.business-policy-match.v1",
                    "version":1,"services":["google_gmail"],"operations":["mail_send"]}},
                "lifetime":{"mode":"until","expiresAt":"2026-07-16T12:00:00.123456789Z"},
                "provenance":{"source":"local","createdAt":"2026-07-15T12:00:00Z"}}]}
    });
    let mut previous: Option<PolicySnapshotV3> = None;
    for source in [source.clone(), {
        let mut changed = source;
        changed["metadata"]["revision"] = json!(2);
        changed["spec"]["rules"][0]["provenance"]["source"] = json!("cloud");
        changed
    }] {
        let compiled = compile_business_document(&source).unwrap();
        let mut value = request();
        value["business_policy"] = serde_json::to_value(compiled.binding()).unwrap();
        let bytes = build(&value).unwrap();
        let snapshot: PolicySnapshotV3 = serde_json::from_slice(&bytes).unwrap();
        validate_v3(
            &snapshot,
            4,
            &"a".repeat(64),
            &"b".repeat(64),
            &[7; 32],
            200,
        )
        .unwrap();
        let binding = snapshot.business_policy.as_ref().unwrap();
        assert_eq!(
            binding.source_document_digest.as_deref(),
            Some(compiled.source_digest())
        );
        assert_eq!(
            binding.rules[0].expires_at.as_deref(),
            Some("2026-07-16T12:00:00.123456789Z")
        );
        let inspected: Value =
            serde_json::from_slice(&super::inspect::inspect_from_reader(bytes.as_slice()).unwrap())
                .unwrap();
        assert_eq!(inspected["authenticity"], "not_checked");
        assert_eq!(inspected["currentness"], "not_checked");
        assert_eq!(inspected["policy_digest"], snapshot.policy_digest);
        if let Some(previous) = previous {
            assert_eq!(previous.config_digest, snapshot.config_digest);
            assert_ne!(previous.policy_digest, snapshot.policy_digest);
            assert_ne!(previous.integrity.mac, snapshot.integrity.mac);
        }
        let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
        tampered["business_policy"]["sourceDocumentDigest"] = json!("f".repeat(64));
        let inspected: Value = serde_json::from_slice(
            &super::inspect::inspect_from_reader(serde_json::to_vec(&tampered).unwrap().as_slice())
                .unwrap(),
        )
        .unwrap();
        assert_ne!(inspected["policy_digest"], tampered["policy_digest"]);
        let tampered: PolicySnapshotV3 = serde_json::from_value(tampered).unwrap();
        assert!(validate_v3(
            &tampered,
            4,
            &"a".repeat(64),
            &"b".repeat(64),
            &[7; 32],
            200
        )
        .is_err());
        previous = Some(snapshot);
    }
}

#[test]
fn budget_declarations_survive_signing_but_invalid_limits_refuse() {
    let mut value = request();
    value["business_policy"]["budgets"] = json!([{
        "schema":guard_policy_snapshot::business_budget::BUSINESS_BUDGET_SCHEMA,
        "version":1,"id":"mail.daily","scope":"account",
        "match":{"schema":"guard.business-policy-match.v1","version":1,
            "services":["google_gmail"],"operations":["mail_send"]},
        "windowMs":86400000,"maximumActions":10,"maximumRecipients":20,
        "maximumRecords":10,"maximumBytes":1048576
    }]);
    let snapshot: Value = serde_json::from_slice(&build(&value).unwrap()).unwrap();
    assert_eq!(
        snapshot["business_policy"]["budgets"],
        value["business_policy"]["budgets"]
    );
    value["business_policy"]["budgets"][0]["windowMs"] = json!(0);
    assert_eq!(build(&value), Err(ERROR.into()));
}

#[test]
fn malformed_and_weakened_inputs_return_only_bounded_error() {
    for patch in [
        json!({"generation":0}),
        json!({"mode":"bypass"}),
        json!({"expires_at_ms":100}),
        json!({"business_policy":null}),
        json!({"verifier_key":[1]}),
        json!({"arbitrary_path":"private-canary"}),
    ] {
        let mut value = request();
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert_eq!(build(&value), Err(ERROR.into()));
    }
    let mut invalid = request();
    invalid["business_policy"]["rules"][0]["action"] = json!("bypass");
    assert_eq!(build(&invalid), Err(ERROR.into()));
    let duplicate = serde_json::to_string(&request())
        .unwrap()
        .replacen("{", "{\"version\":1,", 1);
    assert_eq!(build_from_reader(duplicate.as_bytes()), Err(ERROR.into()));
}

#[test]
fn raw_input_is_bounded_before_decoding_and_io_errors_are_finite() {
    let oversized = vec![b' '; POLICY_SNAPSHOT_MAX_BYTES + 1];
    assert_eq!(build_from_reader(oversized.as_slice()), Err(ERROR.into()));
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private-read-canary"))
        }
    }
    assert_eq!(build_from_reader(Broken), Err(ERROR.into()));
}
