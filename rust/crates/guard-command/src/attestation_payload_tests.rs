//! The order the payload gate reads its rules in, and what it says when one fails.

use serde_json::{json, Map, Value};

use super::attestation_payload::{
    validate_attestation_payload, AttestationPayloadRules, GUARD_TRUST_ATTESTATION_DOMAIN,
    GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3,
};

const BUILDER: AttestationPayloadRules = AttestationPayloadRules::BUILDER;

/// A payload the gate accepts, before a case spoils one field of it.
fn payload() -> Map<String, Value> {
    let Value::Object(fields) = json!({
        "payloadVersion": GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3,
        "domainSeparator": GUARD_TRUST_ATTESTATION_DOMAIN,
        "agentId": "agent-1",
        "itemId": "item-1",
        "itemKind": "skill",
        "contentHash": "a",
        "capturedAt": "2026-10-23T12:00:00Z",
        "claimHash": "b",
        "evidenceHash": "c",
        "scope": "trust_resolution",
    }) else {
        unreachable!("the literal above is an object");
    };
    fields
}

fn refusal(fields: Map<String, Value>, rules: AttestationPayloadRules) -> String {
    validate_attestation_payload(&fields, rules)
        .expect_err("the payload should have been refused")
        .message()
        .to_owned()
}

#[test]
fn an_accepted_payload_comes_back_with_its_strings_stripped() {
    let mut fields = payload();
    fields.insert("agentId".to_owned(), json!("  agent-1\t"));
    let normalized = validate_attestation_payload(&fields, BUILDER).expect("accepted");
    assert_eq!(normalized["agentId"], json!("agent-1"));
    assert_eq!(normalized["itemKind"], json!("skill"));
}

#[test]
fn an_unknown_field_is_named_before_a_missing_one() {
    let mut fields = payload();
    fields.remove("agentId");
    fields.insert("zeta".to_owned(), json!("x"));
    fields.insert("alpha".to_owned(), json!("y"));
    assert_eq!(
        refusal(fields, BUILDER),
        "Unknown trust attestation payload fields: alpha, zeta"
    );
}

#[test]
fn a_missing_required_field_is_named_in_sorted_order() {
    let mut fields = payload();
    fields.remove("itemId");
    fields.remove("agentId");
    assert_eq!(
        refusal(fields, BUILDER),
        "Missing trust attestation payload fields: agentId, itemId"
    );
}

#[test]
fn a_field_that_is_not_a_non_empty_string_is_named() {
    for spoiled in [json!(""), json!("   "), json!(5), Value::Null] {
        let mut fields = payload();
        fields.insert("agentId".to_owned(), spoiled.clone());
        assert_eq!(
            refusal(fields, BUILDER),
            "Trust attestation payload field agentId must be a non-empty string",
            "{spoiled} should not pass as a name"
        );
    }
}

#[test]
fn a_blank_version_is_refused_as_a_string_before_it_is_read_as_a_version() {
    let mut fields = payload();
    fields.insert("payloadVersion".to_owned(), json!(" "));
    assert_eq!(
        refusal(fields, BUILDER),
        "Trust attestation payload field payloadVersion must be a non-empty string"
    );
}

#[test]
fn the_scope_is_read_before_the_capture_time() {
    let mut fields = payload();
    fields.insert("scope".to_owned(), json!("trust_other"));
    fields.insert("capturedAt".to_owned(), json!("not-a-time"));
    assert_eq!(
        refusal(fields, BUILDER),
        "Unsupported trust attestation scope"
    );
}

#[test]
fn a_capture_time_without_a_zone_is_refused() {
    let mut fields = payload();
    fields.insert("capturedAt".to_owned(), json!("2026-10-23T12:00:00"));
    assert_eq!(
        refusal(fields, BUILDER),
        "Trust attestation capturedAt is invalid"
    );
}

#[test]
fn the_builder_refuses_a_payload_that_already_carries_a_signing_time() {
    let mut fields = payload();
    fields.insert("signedAt".to_owned(), json!("2026-10-23T12:00:01Z"));
    assert_eq!(
        refusal(fields.clone(), BUILDER),
        "Trust attestation builder cannot accept signedAt"
    );
    let verifier = AttestationPayloadRules {
        require_signed_at: true,
        ..BUILDER
    };
    assert!(validate_attestation_payload(&fields, verifier).is_ok());
}

#[test]
fn a_verifier_payload_without_a_signing_time_is_refused() {
    let verifier = AttestationPayloadRules {
        require_signed_at: true,
        ..BUILDER
    };
    assert_eq!(
        refusal(payload(), verifier),
        "Trust attestation signedAt is invalid"
    );
}

#[test]
fn a_required_nonce_is_named_when_it_is_absent() {
    let rules = AttestationPayloadRules {
        require_nonce: true,
        ..BUILDER
    };
    assert_eq!(
        refusal(payload(), rules),
        "Trust attestation nonce is required"
    );
    let mut fields = payload();
    fields.insert("nonce".to_owned(), json!("nonce-1"));
    assert!(validate_attestation_payload(&fields, rules).is_ok());
}

#[test]
fn only_the_subject_bindings_that_are_absent_are_named() {
    let rules = AttestationPayloadRules {
        require_subject_bindings: true,
        ..BUILDER
    };
    let mut fields = payload();
    fields.insert("adapterId".to_owned(), json!("adapter-1"));
    fields.insert("policyVersion".to_owned(), json!("policy-7"));
    assert_eq!(
        refusal(fields, rules),
        "Missing trust attestation subject bindings: adapterVersion, configPathHash, repositoryId"
    );
}

#[test]
fn a_sequence_has_to_be_a_whole_number_that_is_not_negative() {
    for refused in [
        json!(-1),
        json!(1.0),
        json!("3"),
        json!(true),
        json!(false),
        Value::Null,
    ] {
        let mut fields = payload();
        fields.insert("sequence".to_owned(), refused.clone());
        assert_eq!(
            refusal(fields, BUILDER),
            "Trust attestation sequence must be a non-negative integer",
            "{refused} should not pass as a sequence"
        );
    }
    // `json.loads` reads `-0` as the `int` `0`, and `0 < 0` is false, so the
    // sign alone is not a refusal. Only a literal read back out of JSON keeps
    // it: `json!(-0)` is the `i64` `0` before serde_json ever sees it.
    let negative_zero: Value = serde_json::from_str("-0").expect("a number");
    let huge: Value = serde_json::from_str("123456789012345678901234567890").expect("a number");
    for accepted in [json!(0), json!(5), negative_zero, huge] {
        let mut fields = payload();
        fields.insert("sequence".to_owned(), accepted.clone());
        assert!(
            validate_attestation_payload(&fields, BUILDER).is_ok(),
            "{accepted} should pass as a sequence"
        );
    }
}

#[test]
fn a_field_is_stripped_the_way_python_strips_it() {
    let mut fields = payload();
    // U+001C to U+001F are whitespace to `str.strip` and not to `str::trim`,
    // so a field padded with one has to come out the same length on both
    // sides: the canonical bytes the signature covers are built from it.
    fields.insert("agentId".to_owned(), json!("\u{1c}\u{1f} agent-1 \u{1e}"));
    let validated = validate_attestation_payload(&fields, BUILDER).expect("accepted");
    assert_eq!(
        validated.get("agentId").and_then(Value::as_str),
        Some("agent-1")
    );

    let mut blank = payload();
    blank.insert("agentId".to_owned(), json!("\u{1c}\u{1d}\u{1e}\u{1f}"));
    assert_eq!(
        refusal(blank, BUILDER),
        "Trust attestation payload field agentId must be a non-empty string"
    );
}

#[test]
fn layer_identity_has_to_match_the_scope() {
    let mut layer = payload();
    layer.insert("scope".to_owned(), json!("trust_layer"));
    assert_eq!(
        refusal(layer.clone(), BUILDER),
        "Trust layer attestation requires layer identity"
    );
    layer.insert("layerId".to_owned(), json!("layer-1"));
    assert_eq!(
        refusal(layer.clone(), BUILDER),
        "Trust layer attestation requires layer identity"
    );
    layer.insert("layerType".to_owned(), json!("skill"));
    assert!(validate_attestation_payload(&layer, BUILDER).is_ok());

    let mut resolution = payload();
    resolution.insert("layerType".to_owned(), json!("skill"));
    assert_eq!(
        refusal(resolution, BUILDER),
        "Trust resolution attestation cannot contain layer identity"
    );
}
