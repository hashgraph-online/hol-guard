use super::wire_v1::{
    build, canonical, canonical_extensions, catalog_digest, evaluate, validate, Refusal,
};
use serde_json::{json, Value};

const FIXTURES: &str =
    include_str!("../../../../contracts/managed-controls/v1/extension-catalog.fixtures.json");
/// Pinned from the previous Python projection of `registry(false)`.
const REGISTRY_DIGEST: &str = "a7caf8d1c4eba405cece0b9ad78ad43b85458b5bb0f78855b42a0919655c3d1a";

fn fixtures() -> Value {
    serde_json::from_str(FIXTURES).unwrap()
}

fn valid() -> Value {
    fixtures()["valid"].clone()
}

fn invalid(message: &str) -> Refusal {
    Refusal::Invalid(message.to_owned())
}

fn redigest(payload: &mut Value) {
    payload["catalogDigest"] = json!(catalog_digest(&payload["extensions"]).unwrap());
}

fn registry(reverse: bool) -> Value {
    let package = json!({
        "extension_id": "command.package-manager", "version": "1.0.0", "name": "Package manager",
        "source": "built-in", "executables": ["pnpm", "npm"], "ecosystem_ids": ["npm"],
        "risk_classes": ["supply_chain"], "delegated_protection": "package-firewall",
        "description": "PRIVATE-SENTINEL",
        "permissions": [{
            "extension_id": "command.package-manager",
            "permission_id": "command.package-manager.permission.package-protection",
            "label": "Package protection", "configurable": true, "risk_tier": "high",
            "typed_capabilities": [],
        }],
    });
    let shell = json!({
        "extension_id": "command.shell", "version": "2.0.0", "name": "Shell",
        "source": "built-in", "executables": ["zsh", "bash", "bash"], "ecosystem_ids": ["posix"],
        "risk_classes": ["destructive", "execution"], "delegated_protection": null,
        "permissions": [{
            "extension_id": "command.shell", "permission_id": "command.shell.permission.execute",
            "label": "Execute shell", "configurable": false, "risk_tier": "critical",
            "typed_capabilities": ["process.spawn", "process.exec"],
        }],
    });
    if reverse {
        json!([shell, package])
    } else {
        json!([package, shell])
    }
}

#[test]
fn projection_is_order_independent_and_matches_the_pinned_digest() {
    let first = build(&registry(false), "3.0.0a1", "2026-08-23T12:00:00Z").unwrap();
    let second = build(&registry(true), "3.0.0a1", "2026-08-23T12:00:01Z").unwrap();
    assert_eq!(first["catalogDigest"], REGISTRY_DIGEST);
    assert_eq!(first["catalogDigest"], second["catalogDigest"]);
    let ids: Vec<_> = first["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["command.package-manager", "command.shell"]);
    assert_eq!(first["controlSchemaVersion"], "guard.extension-controls.v1");
    assert_eq!(first["schemaVersion"], "guard.extension-catalog.v1");
}

#[test]
fn projection_carries_only_privacy_safe_metadata() {
    let payload = build(&registry(false), "3.0.0a1", "2026-08-23T12:00:00Z").unwrap();
    let encoded = String::from_utf8(canonical(&payload)).unwrap();
    for forbidden in [
        "description",
        "rules",
        "ruleIds",
        "exampleCommand",
        "projectMarkers",
        "referenceUrls",
        "sourcePath",
        "workingDirectory",
        "environment",
        "secrets",
        "PRIVATE-SENTINEL",
    ] {
        assert!(!encoded.contains(forbidden), "{forbidden}");
    }
    assert_eq!(
        payload["extensions"][0]["delegatedProtection"],
        "package-firewall"
    );
}

#[test]
fn projection_sorts_set_like_fields_and_preserves_fixed_floors() {
    let payload = build(&registry(false), "3.0.0a1", "2026-08-23T12:00:00Z").unwrap();
    let shell = &payload["extensions"][1];
    assert_eq!(shell["executables"], json!(["bash", "zsh"]));
    assert_eq!(shell["riskClasses"], json!(["destructive", "execution"]));
    let permission = &shell["permissions"][0];
    assert_eq!(permission["required"], true);
    assert_eq!(permission["riskClasses"], json!(["critical"]));
    assert_eq!(
        permission["typedCapabilities"],
        json!(["process.exec", "process.spawn"])
    );
    assert_eq!(shell["deprecated"], false);
    assert!(shell["replacementId"].is_null());
}

#[test]
fn projection_limits_are_limit_refusals() {
    let many: Vec<Value> = (0..513)
        .map(|index| {
            json!({"extension_id": format!("command.scale-{index:06}"), "version": "1.0.0",
            "name": "Scale", "source": "built-in", "executables": [], "ecosystem_ids": [],
            "risk_classes": [], "delegated_protection": null, "permissions": []})
        })
        .collect();
    assert_eq!(
        build(&json!(many), "1", "2026-08-23T12:00:00Z"),
        Err(Refusal::Limit(
            "Extension catalog limit exceeded".to_owned()
        ))
    );
    let permissions: Vec<Value> = (0..513)
        .map(|index| {
            json!({"permission_id": format!("command.wide.permission.p{index}"), "label": "P",
            "configurable": true, "risk_tier": "low", "typed_capabilities": []})
        })
        .collect();
    let wide = json!([{"extension_id": "command.wide", "version": "1.0.0", "name": "Wide",
        "source": "built-in", "executables": [], "ecosystem_ids": [], "risk_classes": [],
        "delegated_protection": null, "permissions": permissions}]);
    assert_eq!(
        build(&wide, "1", "2026-08-23T12:00:00Z"),
        Err(Refusal::Limit(
            "Extension catalog permission limit exceeded".to_owned()
        ))
    );
}

#[test]
fn shared_fixture_is_canonically_executable() {
    let payload = valid();
    let parsed = validate(&payload).unwrap();
    assert_eq!(parsed, payload);
    let digest = super::hash(&canonical(&parsed["extensions"]));
    assert_eq!(parsed["catalogDigest"], digest);
}

#[test]
fn shared_cross_language_canonicalization_vector_is_exact() {
    let vector = fixtures()["canonicalizationVectors"][0].clone();
    let bytes = canonical_extensions(&vector["extensions"]).unwrap();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        vector["canonicalJson"].as_str().unwrap()
    );
    assert_eq!(
        catalog_digest(&vector["extensions"]).unwrap(),
        vector["catalogDigest"].as_str().unwrap()
    );
}

#[test]
fn canonical_bytes_are_sorted_compact_utf8_with_lowercase_control_escapes() {
    let value = json!({"b": "\u{1f}é\n", "a": [1, {"d": null, "c": true}]});
    assert_eq!(
        String::from_utf8(canonical(&value)).unwrap(),
        "{\"a\":[1,{\"c\":true,\"d\":null}],\"b\":\"\\u001fé\\n\"}"
    );
}

#[test]
fn unicode_is_canonicalized_as_utf8() {
    let mut payload = valid();
    payload["extensions"][0]["name"] = json!("Git protection — café");
    redigest(&mut payload);
    let parsed = validate(&payload).unwrap();
    assert!(String::from_utf8(canonical(&parsed))
        .unwrap()
        .contains("café"));
}

#[test]
fn shared_invalid_generated_at_mutation_fails() {
    let mutation = fixtures()["invalidMutations"][0].clone();
    let mut payload = valid();
    payload[mutation["field"].as_str().unwrap()] = mutation["value"].clone();
    assert_eq!(
        validate(&payload),
        Err(invalid("Invalid Extension catalog generatedAt"))
    );
}

#[test]
fn non_ascii_digits_in_generated_at_fail() {
    let mut payload = valid();
    payload["generatedAt"] = json!("2026-10-21T1\u{0662}:00:00Z");
    assert_eq!(
        validate(&payload),
        Err(invalid("Invalid Extension catalog generatedAt"))
    );
}

#[test]
fn shared_invalid_catalog_cases_fail_with_stable_reasons() {
    let cases = fixtures()["invalid"].clone();
    for (case, expected) in [
        (
            "duplicateExtension",
            invalid("Duplicate Extension catalog identity"),
        ),
        (
            "duplicatePermission",
            invalid("Duplicate Extension permission identity"),
        ),
        (
            "unknownField",
            invalid("Extension catalog contains unknown fields"),
        ),
        (
            "oversized",
            Refusal::Limit("Extension catalog payload limit exceeded".to_owned()),
        ),
        (
            "privateField",
            invalid("private Extension catalog field: sourcePath"),
        ),
    ] {
        assert!(cases.get(case).is_some(), "{case}");
        let mut payload = valid();
        let extension = payload["extensions"][0].clone();
        match case {
            "duplicateExtension" => {
                payload["extensions"]
                    .as_array_mut()
                    .unwrap()
                    .push(extension);
                redigest(&mut payload);
            }
            "duplicatePermission" => {
                let permission = extension["permissions"][0].clone();
                payload["extensions"][0]["permissions"]
                    .as_array_mut()
                    .unwrap()
                    .push(permission);
                redigest(&mut payload);
            }
            "unknownField" => payload["unexpected"] = json!(true),
            // The size check runs first, so an oversized body fails on size.
            "oversized" => payload["unexpected"] = json!("x".repeat(1_000_001)),
            _ => payload["sourcePath"] = json!("/private/workspace"),
        }
        assert_eq!(validate(&payload), Err(expected), "{case}");
    }
}

#[test]
fn nested_private_fields_are_rejected_before_shape() {
    let mut payload = valid();
    payload["extensions"][0]["permissions"][0]["working_directory"] = json!("/w");
    assert_eq!(
        validate(&payload),
        Err(invalid(
            "private Extension catalog field: working_directory"
        ))
    );
}

#[test]
fn identities_over_the_shared_schema_limit_are_rejected() {
    let long = format!("command.{}", "a".repeat(300));
    let mut payload = valid();
    payload["extensions"][0]["id"] = json!(long);
    payload["extensions"][0]["permissions"][0]["id"] = json!(format!("{long}.permission.push"));
    redigest(&mut payload);
    assert_eq!(
        validate(&payload),
        Err(invalid("Invalid Extension catalog identity"))
    );
    let mut payload = valid();
    payload["extensions"][0]["permissions"][0]["id"] =
        json!(format!("command.git.permission.{}", "a".repeat(300)));
    redigest(&mut payload);
    assert_eq!(
        validate(&payload),
        Err(invalid("Invalid Extension permission identity"))
    );
}

#[test]
fn entry_rules_keep_their_reasons() {
    let cases: [(&str, Value, &str); 7] = [
        (
            "source",
            json!("remote"),
            "Invalid Extension catalog source",
        ),
        (
            "delegatedProtection",
            json!("other"),
            "Invalid Extension delegated protection",
        ),
        (
            "deprecated",
            json!(0),
            "Invalid Extension deprecation state",
        ),
        (
            "replacementId",
            json!("command.other"),
            "Invalid Extension replacement",
        ),
        (
            "executables",
            json!(["git", "git"]),
            "Duplicate Extension catalog executables",
        ),
        (
            "ecosystemIds",
            json!([""]),
            "Invalid Extension catalog ecosystemIds",
        ),
        ("version", json!(""), "Invalid Extension catalog version"),
    ];
    for (field, value, message) in cases {
        let mut payload = valid();
        payload["extensions"][0][field] = value;
        redigest(&mut payload);
        assert_eq!(validate(&payload), Err(invalid(message)), "{field}");
    }
    let mut payload = valid();
    payload["extensions"][0]["deprecated"] = json!(true);
    payload["extensions"][0]["replacementId"] = json!("command.other");
    redigest(&mut payload);
    assert_eq!(
        validate(&payload),
        Err(invalid(
            "Extension replacement is not present in the catalog"
        ))
    );
    let mut payload = valid();
    payload["extensions"][0]["permissions"][0]["required"] = json!("yes");
    redigest(&mut payload);
    assert_eq!(
        validate(&payload),
        Err(invalid("Invalid Extension permission state"))
    );
    let mut payload = valid();
    payload["extensions"][0]["permissions"][0]["typedCapabilities"] = json!([""]);
    redigest(&mut payload);
    assert_eq!(
        validate(&payload),
        Err(invalid(
            "Invalid Extension catalog permission typedCapabilities"
        ))
    );
}

#[test]
fn envelope_rules_keep_their_reasons() {
    assert_eq!(
        validate(&json!([])),
        Err(invalid("Extension catalog must be an object"))
    );
    for (field, value, message) in [
        (
            "schemaVersion",
            json!("guard.extension-catalog.v2"),
            "Unsupported Extension catalog schema",
        ),
        (
            "catalogDigest",
            json!("A".repeat(64)),
            "Invalid Extension catalog digest",
        ),
        (
            "guardVersion",
            json!(""),
            "Invalid Extension catalog guardVersion",
        ),
        (
            "controlSchemaVersion",
            json!("x".repeat(129)),
            "Invalid Extension catalog controlSchemaVersion",
        ),
        (
            "generatedAt",
            json!("2026-02-29T00:00:00Z"),
            "Invalid Extension catalog generatedAt",
        ),
        (
            "limits",
            json!({"maxExtensions": 1}),
            "Extension catalog limits do not match runtime limits",
        ),
        ("extensions", json!({}), "Extension catalog limit exceeded"),
        (
            "catalogDigest",
            json!("0".repeat(64)),
            "Extension catalog digest does not match canonical bytes",
        ),
    ] {
        let mut payload = valid();
        payload[field] = value;
        assert_eq!(validate(&payload), Err(invalid(message)), "{field}");
    }
}

#[test]
fn limits_compare_numerically_and_render_as_integers() {
    let mut payload = valid();
    payload["limits"]["maxExtensions"] = serde_json::from_str("512.0").unwrap();
    assert_eq!(validate(&payload).unwrap()["limits"], valid()["limits"]);
    payload["limits"]["maxExtensions"] = json!(true);
    assert_eq!(
        validate(&payload),
        Err(invalid(
            "Extension catalog limits do not match runtime limits"
        ))
    );
}

#[test]
fn evaluate_answers_with_payload_refusals() {
    let built = evaluate(&json!({"action": "v1_build", "extensions": registry(false),
        "guard_version": "3.0.0a1", "generated_at": "2026-08-23T12:00:00Z"}));
    assert_eq!(built["schema"], "guard-cloud-catalog-result.v2");
    assert_eq!(
        built["payload"]["catalog"]["catalogDigest"],
        REGISTRY_DIGEST
    );
    let checked = evaluate(&json!({"action": "v1_validate", "payload": valid()}));
    assert_eq!(checked["payload"]["catalog"], valid());
    let mut oversized = valid();
    oversized["unexpected"] = json!("x".repeat(1_000_001));
    let refused = evaluate(&json!({"action": "v1_validate", "payload": oversized}));
    assert_eq!(
        refused["payload"],
        json!({"v1_error": "limit", "message": "Extension catalog payload limit exceeded"})
    );
    let vector = fixtures()["canonicalizationVectors"][0].clone();
    let digest = evaluate(&json!({"action": "v1_canonical", "extensions": vector["extensions"]}));
    assert_eq!(digest["payload"]["canonical_json"], vector["canonicalJson"]);
    assert_eq!(digest["payload"]["catalog_digest"], vector["catalogDigest"]);
    let blank = evaluate(&json!({"action": "v1_build", "extensions": [],
        "guard_version": " ", "generated_at": "2026-08-23T12:00:00Z"}));
    assert_eq!(blank["payload"]["v1_error"], "invalid");
    // The shared dispatcher routes v1 actions without any guard home state.
    let routed = super::evaluate(&json!({"action": "v1_validate", "payload": valid()}));
    assert_eq!(routed["payload"]["catalog"], valid());
}
