use super::*;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("scoped_authority_match_fixture.json")).unwrap()
}

fn request(value: &Value) -> Result<ScopedPolicyRequest, AuthorityError> {
    let exact = &value["exact"];
    ScopedPolicyRequest::from_native_identity(PolicyIdentityInputs {
        harness: value["harness"].as_str().unwrap(),
        artifact_id: value["artifact_id"].as_str(),
        artifact_hash: value["artifact_hash"].as_str(),
        workspace: value["workspace"].as_str(),
        publisher: value["publisher"].as_str(),
        exact_command_sha256: value["exact_command_sha256"].as_str(),
        exact: ExactPolicyContextInputs {
            artifact_legacy: exact["artifact_legacy"].as_str(),
            runtime: exact["runtime"].as_str(),
            portable: exact["portable"].as_str(),
            global: exact["global"].as_str(),
            approval: exact["approval"].as_str(),
        },
    })
}

fn authority(value: &Value) -> NativePolicyAuthority {
    NativePolicyAuthority::from_slice(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn matches_both_authenticated_python_lookup_modes() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 31);
    for case in cases {
        let authority = authority(&case["authority"]);
        let request = request(&case["request"]).unwrap();
        let selected = authority
            .select_generic(&request, case["now_ms"].as_u64().unwrap())
            .unwrap();
        let value = selected.map(|row| json!({"scope": row.scope(), "action": row.action()}));
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            case["expected"],
            "case {}",
            case["name"]
        );
    }
}

#[test]
fn request_diagnostics_never_print_sensitive_identities() {
    let fixture = fixture();
    let request = request(&fixture["cases"][0]["request"]).unwrap();
    assert_eq!(format!("{request:?}"), "ScopedPolicyRequest { .. }");
}

#[test]
fn rejects_malformed_or_unbounded_request_facts_and_clocks() {
    let fixture = fixture();
    let case = &fixture["cases"][0];
    for field in [
        "harness",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
    ] {
        for invalid in [
            "".to_owned(),
            " synthetic".to_owned(),
            "a\0b".to_owned(),
            "a".repeat(4097),
        ] {
            let mut value = case["request"].clone();
            value[field] = json!(invalid);
            assert!(request(&value).is_err(), "field {field}");
        }
    }
    let request = request(&case["request"]).unwrap();
    assert_eq!(
        authority(&case["authority"]).select_generic(&request, u64::MAX),
        Err(AuthorityError::Integer)
    );
}

#[test]
fn row_identifier_or_source_priority_cannot_override_authenticated_recency() {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "signed-recency-newer")
        .unwrap();
    let mut encoded = case["authority"].clone();
    let rows = encoded["rows"].as_array_mut().unwrap();
    rows.reverse();
    for (index, row) in rows.iter_mut().enumerate() {
        row["decision_id"] = json!(9000 - index);
    }
    let authority = authority(&encoded);
    let request = request(&case["request"]).unwrap();
    assert_eq!(
        authority
            .select_generic(&request, case["now_ms"].as_u64().unwrap())
            .unwrap()
            .unwrap()
            .action(),
        PolicyAction::Allow
    );
}

#[test]
fn missing_request_identity_cannot_match_an_exact_artifact_rule() {
    let fixture = fixture();
    let case = &fixture["cases"][0];
    let mut value = case["request"].clone();
    value["artifact_id"] = Value::Null;
    let request = request(&value).unwrap();
    assert!(authority(&case["authority"])
        .select_generic(&request, case["now_ms"].as_u64().unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn exact_context_does_not_erase_the_family_condition() {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "local-family-context-token")
        .unwrap();
    let mut value = case["request"].clone();
    value["artifact_id"] = json!("codex:project:prompt:synthetic-other-family");
    let request = request(&value).unwrap();
    assert!(authority(&case["authority"])
        .select_generic(&request, case["now_ms"].as_u64().unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn malformed_or_unbound_exact_contexts_are_rejected() {
    let fixture = fixture();
    let original = &fixture["cases"][0]["request"];
    for key in ["artifact_legacy", "runtime", "portable", "global"] {
        let mut value = original.clone();
        value["exact"][key] = json!("runtime-exact:not-a-digest");
        assert!(request(&value).is_err(), "key {key}");
    }
    let mut unrelated = original.clone();
    unrelated["exact"]["approval"] = json!("guard-approval-context:v1:unrelated");
    assert!(request(&unrelated).is_err());
    let mut unbound = original.clone();
    unbound["artifact_hash"] = Value::Null;
    assert!(request(&unbound).is_err());
}

#[test]
fn exact_command_is_an_additional_predicate_without_replacing_original_identity() {
    let fixture = fixture();
    let case = &fixture["cases"][0];
    let mut encoded = case["authority"].clone();
    let digest = "a".repeat(64);
    encoded["rows"][0]["exact_command_sha256"] = json!(digest);
    let policy = authority(&encoded);
    for candidate in [Value::Null, json!("b".repeat(64)), json!(digest)] {
        let mut value = case["request"].clone();
        value["exact_command_sha256"] = candidate.clone();
        let request = request(&value).unwrap();
        assert_eq!(
            policy
                .select_generic(&request, case["now_ms"].as_u64().unwrap())
                .unwrap()
                .is_some(),
            candidate == json!(digest)
        );
    }
    for (field, mismatch) in [
        ("artifact_id", "codex:project:tool-action:other"),
        ("harness", "cursor"),
        ("artifact_hash", "other-hash"),
    ] {
        let mut value = case["request"].clone();
        value["exact_command_sha256"] = json!(digest);
        value[field] = json!(mismatch);
        assert!(policy
            .select_generic(&request(&value).unwrap(), case["now_ms"].as_u64().unwrap())
            .unwrap()
            .is_none());
    }
}

#[test]
fn malformed_exact_command_request_digest_cannot_match() {
    let fixture = fixture();
    for invalid in [
        "".to_owned(),
        "a".repeat(63),
        "A".repeat(64),
        format!(" {}", "a".repeat(64)),
    ] {
        let mut value = fixture["cases"][0]["request"].clone();
        value["exact_command_sha256"] = json!(invalid);
        assert!(request(&value).is_err());
    }
}

#[test]
fn exact_command_cannot_erase_the_workspace_predicate() {
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "workspace-family")
        .unwrap();
    let mut encoded = case["authority"].clone();
    encoded["rows"][0]["artifact_id"] = case["request"]["artifact_id"].clone();
    encoded["rows"][0]["exact_command_sha256"] = json!("a".repeat(64));
    let policy = authority(&encoded);
    let mut value = case["request"].clone();
    value["exact_command_sha256"] = json!("a".repeat(64));
    let now = case["now_ms"].as_u64().unwrap();
    assert!(policy
        .select_generic(&request(&value).unwrap(), now)
        .unwrap()
        .is_some());
    value["workspace"] = json!("other-workspace");
    assert!(policy
        .select_generic(&request(&value).unwrap(), now)
        .unwrap()
        .is_none());
    value["workspace"] = Value::Null;
    assert!(policy
        .select_generic(&request(&value).unwrap(), now)
        .unwrap()
        .is_none());
}
