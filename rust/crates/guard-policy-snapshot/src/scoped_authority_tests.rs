use super::*;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("scoped_authority_fixture.json")).unwrap()
}

fn fixture_authority() -> Value {
    fixture()["authority"].clone()
}

fn decode(value: &Value) -> Result<NativePolicyAuthority, AuthorityError> {
    NativePolicyAuthority::from_slice(&serde_json::to_vec(value).unwrap())
}

#[test]
fn accepts_python_compiled_authority_with_matching_content_digest() {
    let fixture = fixture();
    let authority = decode(&fixture["authority"]).unwrap();
    assert_eq!(authority.rows().len(), 3);
    assert_eq!(authority.rows()[0].decision_id(), 1);
    assert_eq!(authority.rows()[0].scope(), PolicyScope::Workspace);
    assert_eq!(authority.rows()[0].action(), PolicyAction::Block);
    assert_eq!(
        authority.managed().unwrap().catalog_digest(),
        "c".repeat(64)
    );
    assert_eq!(
        authority.content_digest().unwrap(),
        fixture["content_digest"]
    );
    assert_eq!(
        serde_json::to_value(&authority).unwrap(),
        fixture["authority"]
    );
}

#[test]
fn debug_output_contains_no_selectors() {
    let authority = decode(&fixture_authority()).unwrap();
    for debug in [
        format!("{authority:?}"),
        format!("{:?}", authority.rows()),
        format!("{:?}", authority.managed()),
    ] {
        assert!(!debug.contains("synthetic"));
        assert!(!debug.contains("runtime-exact"));
        assert!(!debug.contains("command."));
    }
}

#[test]
fn rejects_unknown_fields_at_each_contract_level() {
    for path in ["", "/rows/0", "/managed", "/managed/controls/0"] {
        let mut value = fixture_authority();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(true));
        assert!(decode(&value).is_err(), "unknown field at {path}");
    }
}

#[test]
fn rejects_missing_nullable_fields_instead_of_dropping_constraints() {
    for field in [
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "expires_at_ms",
        "exact_command_sha256",
    ] {
        let mut value = fixture_authority();
        value["rows"][0].as_object_mut().unwrap().remove(field);
        assert!(decode(&value).is_err(), "missing {field}");
    }
    let mut value = fixture_authority();
    value.as_object_mut().unwrap().remove("managed");
    assert!(decode(&value).is_err());
}

#[test]
fn exact_command_is_a_bounded_digest_with_an_original_artifact_scope() {
    let original = fixture_authority();
    for invalid in [
        json!(""),
        json!("a".repeat(63)),
        json!("A".repeat(64)),
        json!(true),
    ] {
        let mut value = original.clone();
        value["rows"][0]["exact_command_sha256"] = invalid;
        assert!(decode(&value).is_err());
    }
    let mut value = original;
    value["rows"][0]["exact_command_sha256"] = json!("a".repeat(64));
    assert!(decode(&value).is_ok());
    value["rows"][0]["artifact_id"] = Value::Null;
    assert!(decode(&value).is_err());
    value["rows"][0]["artifact_id"] = json!("family:tool-action");
    value["rows"][0]["scope"] = json!("harness");
    value["rows"][0]["workspace"] = Value::Null;
    assert!(decode(&value).is_err());
}

#[test]
fn rejects_duplicate_json_fields_and_wrong_schema() {
    let encoded = serde_json::to_string(&fixture_authority()).unwrap();
    let duplicate = encoded.replacen('{', "{\"schema\":\"guard-native-policy-authority.v1\",", 1);
    assert!(NativePolicyAuthority::from_slice(duplicate.as_bytes()).is_err());
    for (key, replacement) in [
        ("schema", "unknown"),
        ("generic_precedence", "source-priority"),
    ] {
        let mut value = fixture_authority();
        value[key] = json!(replacement);
        assert!(decode(&value).is_err());
    }
}

#[test]
fn rejects_nonexact_and_out_of_range_numbers() {
    for replacement in [
        json!(true),
        json!(1.0),
        json!(-1),
        json!(0),
        json!(MAX_EXACT_INTEGER + 1),
    ] {
        let mut value = fixture_authority();
        value["rows"][0]["decision_id"] = replacement;
        assert!(decode(&value).is_err());
    }
    for field in ["updated_at_us", "expires_at_ms"] {
        let mut value = fixture_authority();
        value["rows"][0][field] = json!(MAX_EXACT_INTEGER + 1);
        assert!(decode(&value).is_err());
    }
}

#[test]
fn rejects_unknown_actions_scopes_and_sources() {
    for (field, replacement) in [
        ("action", "ignore"),
        ("scope", "device"),
        ("source_kind", "cloud-sync"),
    ] {
        let mut value = fixture_authority();
        value["rows"][0][field] = json!(replacement);
        assert!(decode(&value).is_err());
    }
}

#[test]
fn rejects_unrepresentable_and_selector_broadening() {
    for (field, replacement) in [
        ("workspace", Value::Null),
        ("publisher", json!("another-predicate")),
        ("artifact_id", json!("")),
        ("artifact_hash", json!(" leading-whitespace")),
        ("artifact_hash", json!("nul\0byte")),
        ("artifact_hash", json!("α".repeat(2049))),
    ] {
        let mut value = fixture_authority();
        value["rows"][0][field] = replacement;
        assert!(decode(&value).is_err(), "invalid {field}");
    }
}

#[test]
fn exact_context_flag_must_match_scope_and_source() {
    let mut value = fixture_authority();
    value["rows"][1]["requires_exact_context"] = json!(false);
    assert!(decode(&value).is_err());
    value["rows"][1]["source_kind"] = json!("signed-bundle");
    assert!(decode(&value).is_ok());
    value["rows"][1]["requires_exact_context"] = json!(true);
    assert!(decode(&value).is_err());
}

#[test]
fn requires_local_exact_context_for_each_runtime_family() {
    for family in [
        "file-read",
        "mcp-tool",
        "package-request",
        "prompt",
        "tool-action",
    ] {
        for scope in ["harness", "global"] {
            let mut value = fixture_authority();
            value["rows"][1]["artifact_id"] = json!(format!("family:{family}"));
            value["rows"][1]["scope"] = json!(scope);
            assert!(decode(&value).is_ok());
            value["rows"][1]["requires_exact_context"] = json!(false);
            assert!(decode(&value).is_err());
        }
    }
}

#[test]
fn rejects_duplicate_rows_and_bounded_collection_overflow() {
    let mut value = fixture_authority();
    value["rows"][1]["decision_id"] = value["rows"][0]["decision_id"].clone();
    assert!(decode(&value).is_err());
    let mut value = fixture_authority();
    let template = value["rows"][0].clone();
    value["rows"] = Value::Array(
        (0..=AUTHORITY_MAX_ROWS)
            .map(|index| {
                let mut row = template.clone();
                row["decision_id"] = json!(index + 1);
                row
            })
            .collect(),
    );
    assert!(decode(&value).is_err());
    let template = value["managed"]["controls"][0].clone();
    value["rows"] = json!([]);
    value["managed"]["controls"] = Value::Array(vec![template; AUTHORITY_MAX_CONTROLS + 1]);
    assert!(decode(&value).is_err());
}

#[test]
fn rejects_oversized_input_before_decoding() {
    assert_eq!(
        NativePolicyAuthority::from_slice(&vec![b' '; AUTHORITY_MAX_BYTES + 1]),
        Err(AuthorityError::ByteLimit)
    );
}

#[test]
fn validates_managed_identity_and_control_states() {
    for (path, replacement) in [
        ("/managed/revision", json!(true)),
        ("/managed/managed_revision", json!(MAX_EXACT_INTEGER + 1)),
        ("/managed/catalog_digest", json!("unknown")),
        ("/managed/global_lockdown", json!("true")),
        ("/managed/controls/0/state", json!("allow")),
        ("/managed/controls/0/target_kind", json!("extension")),
        (
            "/managed/controls/0/target_id",
            json!("command..invalid.permission.read"),
        ),
    ] {
        let mut value = fixture_authority();
        *value.pointer_mut(path).unwrap() = replacement;
        assert!(decode(&value).is_err(), "invalid {path}");
    }
    let mut value = fixture_authority();
    let control = value["managed"]["controls"][0].clone();
    value["managed"]["controls"]
        .as_array_mut()
        .unwrap()
        .push(control);
    assert!(decode(&value).is_err());
}

#[test]
fn direct_deserialization_cannot_bypass_semantic_validation() {
    let mut value = fixture_authority();
    value["rows"][0]["workspace"] = Value::Null;
    assert!(serde_json::from_value::<NativePolicyAuthority>(value).is_err());
}

#[test]
fn required_nullable_values_preserve_nulls_and_reject_malformed_inputs() {
    let mut value = fixture_authority();
    value["rows"][0]["scope"] = json!("harness");
    for field in [
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "expires_at_ms",
        "exact_command_sha256",
    ] {
        value["rows"][0][field] = Value::Null;
    }
    value["managed"] = Value::Null;
    let authority = decode(&value).unwrap();
    assert_eq!(serde_json::to_value(&authority).unwrap(), value);
    for path in [
        "/rows/0/artifact_id",
        "/rows/0/artifact_hash",
        "/rows/0/workspace",
        "/rows/0/publisher",
        "/rows/0/expires_at_ms",
        "/rows/0/exact_command_sha256",
        "/managed",
    ] {
        for invalid in [json!(true), json!([]), json!({})] {
            let mut malformed = value.clone();
            *malformed.pointer_mut(path).unwrap() = invalid;
            assert!(decode(&malformed).is_err(), "malformed {path}");
        }
    }
}

#[test]
fn required_nullable_managed_value_retains_duplicate_field_rejection() {
    let encoded = serde_json::to_string(&fixture_authority()).unwrap();
    let duplicate = encoded.replacen(
        "\"managed_revision\":",
        "\"revision\":0,\"managed_revision\":",
        1,
    );
    assert!(NativePolicyAuthority::from_slice(duplicate.as_bytes()).is_err());
}
