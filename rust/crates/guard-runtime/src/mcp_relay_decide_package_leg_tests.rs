//! Which package call the leg decides from, and which one it defers.
//!
//! The resolution, the lane and the receipt are each covered by their own
//! module; what the leg owns is the request a package call is decided from, so
//! these cover the fields a call is refused for missing.

use super::super::{identity, subject};
use super::*;

use guard_command::package_intent_parser::parse_package_intent;
use serde_json::{json, Value};

const CONTROL: &str = "sha256:control";
const COMMAND: &str = "npm install left-pad";

/// A whole package call as the relay re-sends it: the evaluation it performed
/// and the facts of the process it relays for.
fn request() -> McpRelayDecideRequestV1 {
    serde_json::from_value(json!({
        "guard_home": "/guard",
        "workspace": "/work",
        "hash_workspace": "/work",
        "build": {
            "harness": "codex",
            "server_name": "files",
            "tool_name": "bash",
            "source_scope": "project",
            "config_path": "/work/.codex/config.toml",
            "transport": "stdio",
            "server_id": null,
            "server_fingerprint": null,
            "server_identity": null,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": null},
        },
        "arguments": {"format": "mapping", "entries": [["command", COMMAND]]},
        "path": "/usr/bin:/bin",
        "launcher_home": "/home/dev",
        "cwd": "/work",
        "environment": {"PATH": "/usr/bin:/bin"},
        "package_evaluation": {
            "decision": "review",
            "policy_action": "review",
            "reasons": ["package request"],
            "packages": [{"name": "left-pad", "ecosystem": "npm"}],
        },
        "catalog_state": "present",
        "params": {"name": "bash"},
    }))
    .unwrap()
}

/// The bound harness's view, with no override of its own.
fn view() -> HarnessView {
    let config = json!({
        "mode": "enforce",
        "default_action": "warn",
        "artifact_actions": Value::Null,
        "publisher_actions": Value::Null,
        "harness_actions": Value::Null,
        "risk_actions": {},
        "harness_risk_actions": {},
        "security_level": "balanced",
        "protection_posture": "balanced",
        "protection_posture_explicit": false,
        "managed_locked_settings": [],
    });
    let config = config.as_object().expect("object").clone();
    let mut hash_config = config.clone();
    hash_config.insert("managed_policy_hash".to_owned(), json!("sha256:abc"));
    hash_config.insert("managed_policy_status".to_owned(), json!("enforced"));
    HarnessView {
        mode: "enforce".to_owned(),
        config,
        hash_config,
        layers: Vec::new(),
        receipt_redaction_level: None,
    }
}

/// The intent the gate parsed from the same call.
fn intent() -> PackageIntent {
    parse_package_intent(COMMAND, None, None, None, None).expect("the command carries an intent")
}

/// What the leg answers for the request `edit` leaves, with no store open: a
/// call the leg reads whole gets as far as the store, and every other one is
/// refused before it.
fn leg(edit: impl FnOnce(&mut McpRelayDecideRequestV1)) -> Result<Packaged, &'static str> {
    let mut request = request();
    edit(&mut request);
    let view = view();
    let identity = identity(&request, &view, CONTROL.to_owned()).expect("the identity is built");
    let subject = subject::subject(&request, &identity, &view).expect("the subject is built");
    let inputs = package_inputs(
        &request,
        &view,
        None,
        CONTROL,
        &identity,
        &intent(),
        request.package_evaluation.as_ref(),
    )?;
    decide_package_leg(
        &request,
        inputs,
        &subject,
        QueueBinding {
            blocked_request_mode: Some("safe-alternative"),
            redaction_level: view.receipt_redaction_level.as_deref(),
        },
    )
}

#[test]
fn a_whole_package_call_is_decided_against_the_store() {
    assert_eq!(leg(|_| {}).err(), Some(STORE_ABSENT));
}

#[test]
fn a_package_call_sent_without_its_evaluation_defers() {
    assert_eq!(
        leg(|request| request.package_evaluation = None).err(),
        Some(EVALUATION_ABSENT)
    );
}

#[test]
fn a_package_call_without_the_relaying_process_s_facts_defers() {
    // The workspace the policy lookup is valid for, which no other directory
    // stands in for.
    assert_eq!(
        leg(|request| request.workspace = None).err(),
        Some(FACTS_ABSENT)
    );
    assert_eq!(
        leg(|request| request.workspace = Some(String::new())).err(),
        Some(FACTS_ABSENT)
    );
    assert_eq!(leg(|request| request.cwd = None).err(), Some(FACTS_ABSENT));
    assert_eq!(
        leg(|request| request.cwd = Some(String::new())).err(),
        Some(FACTS_ABSENT)
    );
    assert_eq!(
        leg(|request| request.environment.clear()).err(),
        Some(FACTS_ABSENT)
    );
}
