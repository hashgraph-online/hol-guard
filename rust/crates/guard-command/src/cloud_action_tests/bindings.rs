//! Binding set admission.

use super::*;

// ---- binding set admission ----

fn edited_set(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut set: Value = serde_json::from_str(BINDINGS).unwrap();
    edit(&mut set);
    set.to_string().into_bytes()
}

#[test]
fn the_fixture_binding_set_loads_with_a_stable_digest() {
    let set = load_binding_set(BINDINGS.as_bytes()).unwrap();
    assert_eq!(set.len(), 5);
    assert!(!set.is_empty());
    let post = set.get(POST).unwrap();
    assert_eq!(post.binding.adapter.provider, "slack");
    assert!(is_hex_digest(&Value::from(
        post.execution_identity_digest.as_str()
    )));
    assert!(set.get("slack.chat.unknown").is_none());
    // Spelling and key order do not change the digest.
    let reordered = edited_set(|_| {});
    assert_eq!(load_binding_set(&reordered).unwrap().digest, set.digest);
}

#[test]
fn a_binding_without_egress_pinning_rejects_the_whole_set() {
    let bytes = edited_set(|set| {
        set["bindings"][1]["required_capabilities"] =
            json!(["bounded-output", "resource-allowlist"]);
    });
    assert_eq!(
        load_binding_set(&bytes).unwrap_err(),
        "binding_missing_required_capability"
    );
}

#[test]
fn a_binding_without_bounded_output_rejects_the_whole_set() {
    let bytes = edited_set(|set| {
        set["bindings"][4]["required_capabilities"] = json!(["egress-pinned", "no-filesystem"]);
    });
    assert_eq!(
        load_binding_set(&bytes).unwrap_err(),
        "binding_missing_required_capability"
    );
}

#[test]
fn duplicate_actions_reject_the_whole_set() {
    let bytes = edited_set(|set| {
        let copy = set["bindings"][0].clone();
        set["bindings"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(
        load_binding_set(&bytes).unwrap_err(),
        "binding_duplicate_action"
    );
}

#[test]
fn a_non_https_remote_mcp_url_rejects_the_whole_set() {
    for url in [
        "http://mcp.example.invalid/v1",
        "ws://mcp.example.invalid/v1",
        "mcp.example.invalid/v1",
        "",
    ] {
        let bytes = edited_set(|set| set["bindings"][4]["remote_mcp"]["url"] = url.into());
        assert_eq!(
            load_binding_set(&bytes).unwrap_err(),
            "binding_malformed",
            "{url:?}"
        );
    }
    let bytes = edited_set(|set| set["bindings"][4]["remote_mcp"]["tool_name"] = " ".into());
    assert_eq!(load_binding_set(&bytes).unwrap_err(), "binding_malformed");
}

#[test]
fn adapter_kind_and_remote_mcp_section_must_agree() {
    let native_with_remote = edited_set(|set| {
        set["bindings"][0]["remote_mcp"] =
            json!({"url": "https://mcp.example.invalid/v1", "tool_name": "t"});
    });
    assert_eq!(
        load_binding_set(&native_with_remote).unwrap_err(),
        "binding_malformed"
    );
    let remote_without_section = edited_set(|set| set["bindings"][4]["remote_mcp"] = Value::Null);
    assert_eq!(
        load_binding_set(&remote_without_section).unwrap_err(),
        "binding_malformed"
    );
}

#[test]
fn malformed_bindings_and_sets_are_rejected() {
    let cases: [(&str, Edit, &str); 9] = [
        (
            "set schema",
            |s| s["schema"] = "guard.cloud-action-binding-set.v2".into(),
            "binding_set_unsupported_version",
        ),
        (
            "binding schema",
            |s| s["bindings"][0]["schema"] = "guard.cloud-action-binding.v2".into(),
            "binding_unsupported_version",
        ),
        (
            "set field",
            |s| s["extra"] = 1.into(),
            "binding_set_malformed",
        ),
        (
            "binding field",
            |s| s["bindings"][0]["extra"] = 1.into(),
            "binding_malformed",
        ),
        (
            "action id case",
            |s| s["bindings"][0]["action_id"] = "Slack.Channels.List".into(),
            "binding_malformed",
        ),
        (
            "action id depth",
            |s| s["bindings"][0]["action_id"] = "slack".into(),
            "binding_malformed",
        ),
        (
            "effect",
            |s| s["bindings"][0]["effect"] = "owner".into(),
            "binding_malformed",
        ),
        (
            "input schema",
            |s| s["bindings"][0]["adapter"]["input_schema"] = "object".into(),
            "binding_malformed",
        ),
        (
            "float",
            |s| {
                s["bindings"][0]["adapter"]["input_schema"]["maximum"] =
                    serde_json::from_str("1.5").unwrap()
            },
            "binding_set_malformed",
        ),
    ];
    for (name, edit, code) in cases {
        let bytes = edited_set(edit);
        assert_eq!(load_binding_set(&bytes).unwrap_err(), code, "{name}");
    }
    assert_eq!(load_binding_set(b"").unwrap_err(), "binding_set_malformed");
    assert_eq!(
        load_binding_set(b"[]").unwrap_err(),
        "binding_set_malformed"
    );
    let duplicate_key = BINDINGS.replacen("\"bindings\"", "\"schema\": \"x\", \"bindings\"", 1);
    assert_eq!(
        load_binding_set(duplicate_key.as_bytes()).unwrap_err(),
        "binding_set_malformed"
    );
}

#[test]
fn a_changed_binding_changes_the_set_digest() {
    let original = load_binding_set(BINDINGS.as_bytes()).unwrap();
    let changed = load_binding_set(&edited_set(|set| {
        set["bindings"][0]["effect"] = "write".into()
    }))
    .unwrap();
    assert_ne!(original.digest, changed.digest);
    assert_eq!(
        changed.get(LIST).unwrap().binding.effect,
        ActionEffect::Write
    );
    assert_ne!(
        original.get(LIST).unwrap().execution_identity_digest,
        changed.get(LIST).unwrap().execution_identity_digest
    );
    assert_eq!(
        original.get(POST).unwrap().execution_identity_digest,
        changed.get(POST).unwrap().execution_identity_digest
    );
}
