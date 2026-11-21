//! Saved decisions on the daemon's hook path. The resident selects a rule
//! under its own Guard home and renders its response. The host only supplies
//! the integrity material from the store's keyring when requested.

use std::path::Path;

use guard_command::hook_responses::Object;
use guard_contracts::{PolicyDecisionLookupRequestV1, POLICY_DECISION_LOOKUP_REQUEST_SCHEMA};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

use crate::hook_direct::saved_decision::{render, saved_verdict};
use crate::local_store_read::{open_read_only_cached, STORE_FILE_NAME};
use crate::policy_store::PolicySnapshotStore;

const INVALID: &str = "native_hook_render_invalid";
const RETRY_HINT: &str = "Do not retry it; continue with a permitted alternative.";

enum Check<'a> {
    Action { artifact: &'a str, token: &'a str },
    Command(&'a str),
}

pub(super) fn answer(
    harness: &str,
    inputs: &Object,
    store: Option<&PolicySnapshotStore>,
) -> Result<Object, &'static str> {
    let text = |key: &str| inputs.get(key).and_then(Value::as_str);
    let verdict = inputs
        .get("verdict")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let home = text("guard_home").ok_or(INVALID)?;
    store
        .ok_or(INVALID)?
        .require_guard_home(home)
        .map_err(|_| INVALID)?;
    let store_path = Path::new(home).join(STORE_FILE_NAME);
    let check = match text("check") {
        Some("action") => text("token")
            .zip(text("artifact_id"))
            .map(|(token, artifact)| Check::Action { artifact, token }),
        Some("command")
            if inputs.get("edge_hint") != Some(&Value::Bool(false)) && shell(verdict) =>
        {
            text("command").map(Check::Command)
        }
        Some("command") => None,
        _ => return Err(INVALID),
    };
    let Some(check) = check else {
        return Ok(document(None, false));
    };
    let Some(evidence) = inputs.get("evidence") else {
        let needed = match check {
            Check::Action { artifact, token } => {
                match decision_exists(&store_path, harness, artifact, token) {
                    Ok(exists) => exists,
                    Err(()) => return unreadable(harness, verdict, &check),
                }
            }
            Check::Command(_) => true,
        };
        return Ok(document(None, needed));
    };
    if evidence.get("degraded").and_then(Value::as_bool) == Some(true) {
        return Ok(document(None, false));
    }
    let Some(mut lookup) = lookup_request(harness, home, &store_path, text("workspace"), evidence)
    else {
        return unreadable(harness, verdict, &check);
    };
    let found = match check {
        Check::Action { artifact, token } => {
            lookup.artifact_id = Some(artifact.to_owned());
            lookup.artifact_hash = Some(token.to_owned());
            crate::policy_decision_lookup_op::evaluate_with_bundle(&lookup)
                .map(|lookup| saved_verdict(verdict, &lookup, artifact, token))
        }
        Check::Command(command) => command_block(harness, verdict, command, lookup),
    };
    match found {
        Ok(Some((verdict, status))) => render(harness, &verdict, status)
            .map(|value| document(Some(value), false))
            .ok_or(INVALID),
        Ok(None) => Ok(document(None, false)),
        Err(_) => unreadable(harness, verdict, &check),
    }
}

fn document(value: Option<Value>, needs_lookup: bool) -> Object {
    Object::from_iter([
        ("value".to_owned(), value.unwrap_or(Value::Null)),
        ("needs_lookup".to_owned(), Value::Bool(needs_lookup)),
    ])
}

fn decision_exists(store: &Path, harness: &str, artifact: &str, token: &str) -> Result<bool, ()> {
    let Some(connection) = open_read_only_cached(store).map_err(|_| ())? else {
        return Ok(false);
    };
    connection
        .query_row(
            "select 1 from policy_decisions where harness in (?1, '*') and scope = 'artifact' \
         and artifact_id = ?2 and artifact_hash = ?3 limit 1",
            params![harness, artifact, token],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|_| ())
}

fn lookup_request(
    harness: &str,
    home: &str,
    store_path: &Path,
    workspace: Option<&str>,
    evidence: &Value,
) -> Option<PolicyDecisionLookupRequestV1> {
    // The host does not set the store path, lookup scope, consumability,
    // bundle authority, or identity of the row the resident reads.
    crate::strict_json::from_value(json!({
        "schema": POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
        "store_path": store_path.to_str()?,
        "guard_home": home,
        "harness": harness,
        "workspace": workspace,
        "now": evidence.get("now")?,
        "consume_one_shot": false,
        "integrity_state": evidence.get("integrity_state"),
        "integrity_key_b64": evidence.get("integrity_key_b64"),
        "integrity_key_id": evidence.get("integrity_key_id"),
        "local_once_integrity_key_b64": evidence.get("local_once_integrity_key_b64"),
        "local_once_integrity_key_id": evidence.get("local_once_integrity_key_id"),
    }))
    .ok()
}

fn shell(verdict: &Object) -> bool {
    verdict
        .get("action")
        .and_then(|action| action.get("action_type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| {
            matches!(
                kind,
                "command" | "package" | "process_service" | "network" | "shell" | "shell_command"
            )
        })
}

fn command_block(
    harness: &str,
    verdict: &Object,
    command: &str,
    mut lookup: PolicyDecisionLookupRequestV1,
) -> Result<Option<(Object, &'static str)>, String> {
    let keys = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
        command: Some(command),
        artifact_type: Some("shell_command"),
        artifact_id: None,
        artifact_name: None,
        harness: Some(harness),
    });
    for key in keys.exact_artifact_ids {
        lookup.artifact_id = Some(key.clone());
        let result = crate::policy_decision_lookup_op::evaluate_with_bundle(&lookup)?;
        let Some(decision) = result.get("decision").and_then(Value::as_object) else {
            continue;
        };
        let text = |key| decision.get(key).and_then(Value::as_str);
        if text("scope") == Some("artifact")
            && text("artifact_id") == Some(key.as_str())
            && text("action") == Some("block")
        {
            let (code, reason) =
                if guard_policy_snapshot::policy_integrity::is_remote_policy_source(text("source"))
                {
                    (
                        "policy_exact_command_block",
                        "Your Guard Cloud policy blocks this exact command.",
                    )
                } else {
                    (
                        "saved_exact_command_block",
                        "You chose to always block this exact command in HOL Guard.",
                    )
                };
            return Ok(Some((
                blocked(verdict, code, &format!("{reason} {RETRY_HINT}")),
                "blocked",
            )));
        }
    }
    Ok(None)
}

fn unreadable(harness: &str, verdict: &Object, check: &Check<'_>) -> Result<Object, &'static str> {
    let (code, reason) = match check {
        Check::Action { .. } => (
            "saved_exact_action_unreadable",
            "HOL Guard could not read your saved decision for this exact action.".to_owned(),
        ),
        Check::Command(_) => (
            "saved_exact_command_unreadable",
            format!(
                "HOL Guard could not read the saved block for this exact command. {RETRY_HINT}"
            ),
        ),
    };
    render(harness, &blocked(verdict, code, &reason), "blocked")
        .map(|value| document(Some(value), false))
        .ok_or(INVALID)
}

fn blocked(verdict: &Object, code: &str, reason: &str) -> Object {
    let mut verdict = verdict.clone();
    for (key, value) in [
        ("decision", "deny"),
        ("minimum_action", "block"),
        ("policy_action", "block"),
        ("reason_code", code),
        ("reason", reason),
    ] {
        verdict.insert(key.to_owned(), json!(value));
    }
    verdict
}
