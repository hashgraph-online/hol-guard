//! Parity fixtures for the sensitive tool-action artifact id.
//!
//! Every digest here was produced by the Python builder this module replaces
//! (`hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8"))` over
//! the payload at `benign_requests.py:120-134`), not by this code. They are the
//! keys saved approvals are already stored under, so a change that moves one of
//! them silently drops every approval a user has granted for that action.

use serde_json::json;

use crate::tool_action_identity::{
    tool_action_request_artifact_id, tool_action_request_fingerprint, ToolActionIdentityInputs,
};

/// The shape of a plain package install under the project scope: no shell
/// context hash, no interpreter identities, none of the three optional
/// identities.
fn minimal_inputs() -> ToolActionIdentityInputs {
    ToolActionIdentityInputs {
        harness: "codex".to_owned(),
        source_scope: "project".to_owned(),
        normalized_tool_name: "shell".to_owned(),
        command_text: "npm install left-pad".to_owned(),
        action_class: "package_install".to_owned(),
        shell_execution_context_hash: None,
        interpreter_executable_identities: Vec::new(),
        script_read_identity_sha256: None,
        restricted_profile_version: None,
        pytest_config_identity_sha256: None,
    }
}

#[test]
fn minimal_request_matches_the_python_fingerprint() {
    assert_eq!(
        tool_action_request_fingerprint(&minimal_inputs()),
        "eb1b99795c6bca333d21943b4f502ee7d4d79b05226b08de85823fec068b7d2a"
    );
}

#[test]
fn minimal_request_matches_the_python_artifact_id() {
    assert_eq!(
        tool_action_request_artifact_id(&minimal_inputs()),
        "codex:project:tool-action:\
         eb1b99795c6bca333d21943b4f502ee7d4d79b05226b08de85823fec068b7d2a"
    );
}

#[test]
fn every_optional_identity_present_matches_python() {
    let inputs = ToolActionIdentityInputs {
        harness: "claude".to_owned(),
        source_scope: "global".to_owned(),
        shell_execution_context_hash: Some("a".repeat(64)),
        interpreter_executable_identities: vec![
            json!({"path": "/usr/bin/python3", "status": "resolved", "sha256": "b".repeat(64)}),
            json!({"path": null, "status": "ambiguous"}),
        ],
        script_read_identity_sha256: Some("c".repeat(64)),
        restricted_profile_version: Some("2.1.0".to_owned()),
        pytest_config_identity_sha256: Some("d".repeat(64)),
        ..minimal_inputs()
    };
    assert_eq!(
        tool_action_request_fingerprint(&inputs),
        "f25b683fb2e5498012f0f2051766c38fa8edc47e9377230daa6d4fcd4a264842"
    );
    assert_eq!(
        tool_action_request_artifact_id(&inputs),
        "claude:global:tool-action:\
         f25b683fb2e5498012f0f2051766c38fa8edc47e9377230daa6d4fcd4a264842"
    );
}

/// `json.dumps` escapes non-ASCII by default, and an astral character becomes a
/// surrogate pair. A command text carrying either has to hash to the same value
/// it did in Python or the approval for it is lost.
#[test]
fn non_ascii_command_text_matches_python_escaping() {
    let inputs = ToolActionIdentityInputs {
        command_text: "echo \"café 😀\" > /tmp/x".to_owned(),
        ..minimal_inputs()
    };
    assert_eq!(
        tool_action_request_fingerprint(&inputs),
        "22d0e18b25fc820e497ed56a9aeb29c03fbf451c20c6708410d3be74e9271fa6"
    );
}

/// The payload is encoded with `json.dumps`'s *default* separators, so a
/// command text containing `", "` or `": "` is the case that tells a correct
/// encoder from one that rewrote compact JSON after the fact.
#[test]
fn separator_shaped_command_text_matches_python() {
    let inputs = ToolActionIdentityInputs {
        command_text: "a, b: c".to_owned(),
        ..minimal_inputs()
    };
    assert_eq!(
        tool_action_request_fingerprint(&inputs),
        "7e567c9730955f51c547f6b3ea49cfa5e40af352ea9e2ee44331a1a2896d9088"
    );
}

/// Guards the separator choice directly: the compact codec used elsewhere in
/// this crate produces a different id for the same request.
#[test]
fn compact_separators_would_change_the_id() {
    assert_ne!(
        tool_action_request_fingerprint(&minimal_inputs()),
        "3df8dc5e738dc9ace436b54ed0c93be5a3a6ef22955cced0861c25e48dddd914"
    );
}

/// Python omits an unset optional identity rather than writing it as `null`,
/// and the two encodings hash differently. Emitting the key unconditionally
/// would re-key every request that has no script read.
#[test]
fn an_unset_optional_identity_is_absent_not_null() {
    assert_ne!(
        tool_action_request_fingerprint(&minimal_inputs()),
        "c884335fc9e9ef90a65d5b1ed058ada559e048bf9355f45d29d91e08b13e75cc"
    );
}

/// The scope is part of the key, not decoration: the same action approved in a
/// project must not satisfy a global approval.
#[test]
fn scope_and_harness_separate_otherwise_identical_requests() {
    let project = tool_action_request_artifact_id(&minimal_inputs());
    let global = tool_action_request_artifact_id(&ToolActionIdentityInputs {
        source_scope: "global".to_owned(),
        ..minimal_inputs()
    });
    assert_ne!(project, global);
    // The scope sits outside the fingerprint, which the harness does enter.
    assert_eq!(
        tool_action_request_fingerprint(&minimal_inputs()),
        tool_action_request_fingerprint(&ToolActionIdentityInputs {
            source_scope: "global".to_owned(),
            ..minimal_inputs()
        })
    );
    assert_ne!(
        tool_action_request_fingerprint(&minimal_inputs()),
        tool_action_request_fingerprint(&ToolActionIdentityInputs {
            harness: "claude".to_owned(),
            ..minimal_inputs()
        })
    );
}
