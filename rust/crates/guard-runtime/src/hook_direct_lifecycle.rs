//! Lifecycle hooks the resident answers as the daemon does.
//!
//! The edge reviews tool, prompt and permission hooks only. For any other
//! event, such as Claude Code's `Stop`, Kimi's `SessionStart` or Cline's
//! `TaskStart`, the daemon asks its resident, receives the edge's refusal,
//! and returns `fail_closed_response`: a constant that carries no verdict
//! and depends only on the harness and the event name. This module returns
//! that same constant without the daemon round trip. It never answers a
//! hook the daemon handles itself or answers a lifecycle hook with a deny.
//!
//! Claude Code's `PermissionRequest` is the exception the daemon answers
//! from the session's permission notice. Without a notice row its answer is
//! also a constant, which this module returns. With the daemon's integrity
//! key bound, the resident verifies the notice and marks it seen as the
//! daemon does, then renders the daemon's answer; without the key, or when
//! a row is signed under another key, the session keeps the daemon path.
//!
//! Codex's, Copilot's, Devin's and ZCode's `PermissionRequest` get the
//! daemon's constant passthrough: no decision, so the harness shows its own
//! approval prompt. Each asks it only for a call whose `PreToolUse` hook
//! already reached Guard.
//!
//! Claude Code's `permission_prompt` notification is answered the same way:
//! the notice, when there is one, is verified and marked seen, and the event
//! the daemon records for every such prompt is written in that transaction.
//! Every other Claude notification gets the constant.
//!
//! Claude Code's `Stop` gets the constant too, after the daemon's
//! `claude_turn_stop`: the session's unanswered prompts are dropped and the
//! turn's end is recorded, so the next turn cannot inherit a block nobody
//! chose. Only the bound key verifies the pending index, so a session that
//! has one keeps the daemon path when the key is not bound.

use std::path::Path;
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{HookAuthorityStateRequestV1, HOOK_AUTHORITY_STATE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use super::claude_permission_text::{
    notification_tool_name, permission_prompt_event, permission_prompt_notification_response,
    permission_request_response, PERMISSION_PROMPT_EVENT,
};
use super::workspace::python_strip;
use super::{
    HookDirectDefer, CLAUDE_CODE, CURSOR, EVENT_NAME_FIELDS, GROK, PAYLOAD_REFERENCE_FIELDS,
    TRANSITION_PROBE_FIELD,
};
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::hook_authority_state_op;
use crate::hook_authority_state_op::{
    claude_permission_notice_direct, claude_permission_prompt_direct, claude_turn_stop_direct,
};
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::policy_integrity_generation::lock as policy_generation_lock;
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, finalization_state, load_policy_integrity_control_state,
    policy_integrity_secret_material, POLICY_INTEGRITY_CONTROL_REF,
};
use crate::policy_store::PolicySnapshotStore;

/// The daemon's `reason_code` when the edge does not review an event.
const UNAVAILABLE_REASON_CODE: &str = "native_hook_event_unavailable";
/// `_DECISION_HARNESSES` among the harnesses the resident answers.
const DECISION_HARNESSES: [&str; 4] = ["hermes", "openclaw", "pi", "omp"];
/// Events `fail_closed_response` answers with a deny, or the daemon handles
/// itself.
const DAEMON_EVENTS: [&str; 3] = [
    "permissionrequest",
    "permissionrequestv2",
    "copilotpermissionrequest",
];
/// `runtime_hook_event_name` keeps an unmapped name as sent, so only this
/// exact spelling reaches the daemon's permission prompt handler.
const NOTIFICATION: &str = "Notification";
const PERMISSION_PROMPT: &str = "permission_prompt";
/// The Claude event the daemon ends a turn on.
const STOP: &str = "Stop";
/// Harnesses whose `PermissionRequest` the daemon passes through.
const PASSTHROUGH_PERMISSION_HARNESSES: [&str; 4] = ["codex", "copilot", "devin", "zcode"];
/// The events `runtime_hook_event_name` names `PermissionRequest`.
const CLAUDE_PERMISSION_EVENTS: [&str; 2] = ["permissionrequest", "permissionrequestv2"];
/// A longer or unusual name is left to the daemon.
const MAX_EVENT_NAME_BYTES: usize = 64;
const QUESTION_SETTLE: &str = "claude_question_settle_hook";
const QUESTION_SAVE: &str = "claude_question_save";
const QUESTION_CONSUME: &str = "claude_question_consume";
const QUESTION_LOCK_WAIT: Duration = Duration::from_millis(250);

/// `runtime_hook_event_name` for an event `direct_event` does not review:
/// the first non-blank event field, stripped.
fn event_name(payload: &Map<String, Value>) -> Result<&str, HookDirectDefer> {
    for field in EVENT_NAME_FIELDS {
        let Some(value) = payload.get(field).and_then(Value::as_str) else {
            continue;
        };
        let stripped = python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?;
        if let Some(name) = stripped {
            return Ok(name);
        }
    }
    Err(HookDirectDefer::EventUnsupported)
}

/// The harness response `fail_closed_response` returns for `event`.
pub(crate) fn constant_response(harness: &str, event: &str) -> Value {
    // `fail_closed_response` answers every Grok lifecycle hook with `{}`.
    if harness == GROK {
        return json!({});
    }
    if DECISION_HARNESSES.contains(&harness) {
        return json!({
            "decision": "allow",
            "policy_action": "allow",
            "reason_code": UNAVAILABLE_REASON_CODE,
        });
    }
    json!({
        "continue": true,
        "policy_action": "allow",
        "reason_code": UNAVAILABLE_REASON_CODE,
        "hookSpecificOutput": { "hookEventName": event },
    })
}

/// The daemon's passthrough `PermissionRequest` answer: no decision, so the
/// harness uses its normal approval flow.
fn passthrough_permission_response() -> Value {
    json!({ "hookSpecificOutput": { "hookEventName": "PermissionRequest" } })
}

/// The answer for a hook whose event the edge does not review, when the
/// daemon would return its constant for it.
pub(super) fn answer(
    harness: &str,
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // The Cursor client renders lifecycle hooks through Guard's Python.
    if harness == CURSOR {
        return Err(HookDirectDefer::EventUnsupported);
    }
    let event = event_name(payload)?;
    if event.len() > MAX_EVENT_NAME_BYTES
        || !event
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
    {
        return Err(HookDirectDefer::EventUnsupported);
    }
    let compact = event.replace(['_', '-'], "").to_ascii_lowercase();
    // A session started again after compaction or `/clear` keeps its id but
    // no longer holds the code CIGAR showed it, so later notes send it again.
    if compact == "sessionstart"
        && matches!(
            payload.get("source").and_then(Value::as_str),
            Some("compact" | "clear")
        )
    {
        if let Some(id) = payload.get("session_id").and_then(Value::as_str) {
            crate::context_assistance_prompt::seen::restarted(harness, id.trim());
        }
    }
    let claude_permission =
        harness == CLAUDE_CODE && CLAUDE_PERMISSION_EVENTS.contains(&compact.as_str());
    let passthrough_permission = PASSTHROUGH_PERMISSION_HARNESSES.contains(&harness)
        && CLAUDE_PERMISSION_EVENTS.contains(&compact.as_str());
    if !claude_permission
        && !passthrough_permission
        && (DAEMON_EVENTS.contains(&compact.as_str()) || compact.starts_with("before"))
    {
        return Err(HookDirectDefer::EventUnsupported);
    }
    if payload.contains_key(TRANSITION_PROBE_FIELD) {
        return Err(HookDirectDefer::TransitionProbe);
    }
    if PAYLOAD_REFERENCE_FIELDS
        .iter()
        .any(|field| payload.contains_key(*field))
    {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    // A daemon that has published no direct-lane binding answers itself.
    policy_store
        .direct_lane_home_dir()
        .ok_or(HookDirectDefer::BindingIncomplete)?;
    // The daemon passes a hook through for a harness Guard does not manage.
    let store = crate::local_store_read::hook_store_probe(Path::new(guard_home), harness, None)
        .map_err(|_| HookDirectDefer::HarnessUnmanaged)?;
    if store.harness_unmanaged {
        return Err(HookDirectDefer::HarnessUnmanaged);
    }
    if claude_permission {
        return claude_permission_answer(guard_home, payload, policy_store);
    }
    if passthrough_permission {
        return Ok(json!({ "harness_response": passthrough_permission_response() }));
    }
    // `str(payload.get("notification_type") or "") == "permission_prompt"`.
    if harness == CLAUDE_CODE
        && event == NOTIFICATION
        && payload.get("notification_type").and_then(Value::as_str) == Some(PERMISSION_PROMPT)
    {
        return claude_permission_prompt_answer(guard_home, payload, policy_store);
    }
    if harness == CLAUDE_CODE && event == STOP {
        claude_turn_stop_answer(guard_home, payload, policy_store)?;
    }
    // A finished turn wakes it too: the person reads the answer and types the
    // next prompt while CIGAR starts, instead of that prompt paying for it.
    if matches!(compact.as_str(), "sessionstart" | "stop") && !records_only(harness, policy_store) {
        crate::context_assistance_prompt::wake(harness, policy_store);
    }
    Ok(json!({ "harness_response": constant_response(harness, event) }))
}

/// Answer Claude's HOL Guard `AskUserQuestion` in the direct resident lane.
///
/// The daemon used to reach this path through a Python worker bridge. The
/// resident now performs the same settle, signed policy write, integrity
/// finalization and pending-row consume sequence itself. `None` means the
/// payload is an ordinary post-tool event and should continue through the
/// normal direct edge.
pub(crate) fn claude_question_answer(
    guard_home: &str,
    home_dir: Option<&str>,
    payload: &Map<String, Value>,
    deadline: Instant,
) -> Result<Option<Value>, HookDirectDefer> {
    let Some(session_id) = payload
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|value| python_strip(value).ok())
        .flatten()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return Ok(None);
    };
    let Some(question) = question_wire(payload) else {
        return Ok(None);
    };
    let resolved_home = Path::new(guard_home)
        .canonicalize()
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    let store_path = resolved_home.join("guard.db");
    let mut secrets = EncryptedFileSecretStore::new(&resolved_home);
    let Some(material) = policy_integrity_secret_material(&mut secrets, &resolved_home) else {
        return Ok(None);
    };
    let key_b64 = Base64UrlUnpadded::encode_string(&material.raw_key);
    let now = utc_now_isoformat().ok_or(HookDirectDefer::PermissionNotice)?;
    let settle = authority_request(
        &store_path,
        &resolved_home,
        QUESTION_SETTLE,
        &now,
        Some(&session_id),
        Some((&key_b64, &material.key_id)),
        Some(Value::String(question)),
        home_dir,
    )?;
    let reply = hook_authority_state_op::evaluate_within(&settle, remaining(deadline))
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    match settled_reply(&reply)? {
        QuestionSettlement::Answered => return Ok(Some(json!({}))),
        QuestionSettlement::None => return Ok(None),
        QuestionSettlement::Save(mut save) => {
            let control_ref = build_scoped_secret_ref(POLICY_INTEGRITY_CONTROL_REF, &resolved_home);
            let current = match load_policy_integrity_control_state(&mut secrets, &resolved_home) {
                Some(current) => current,
                None => {
                    let initial = json!({
                        "cutover_complete": true,
                        "generation": 0,
                        "pending_generation": null,
                        "version": 1,
                    });
                    secrets
                        .set_secret(
                            &control_ref,
                            &serde_json::to_string(&initial)
                                .map_err(|_| HookDirectDefer::PermissionNotice)?,
                        )
                        .map_err(|_| HookDirectDefer::PermissionNotice)?;
                    initial
                }
            };
            let generation = current
                .get("generation")
                .and_then(Value::as_i64)
                .filter(|value| *value >= 0)
                .ok_or(HookDirectDefer::PermissionNotice)?;
            if !current.get("pending_generation").is_none_or(Value::is_null) {
                return Err(HookDirectDefer::PermissionNotice);
            }
            let next_generation = generation
                .checked_add(1)
                .ok_or(HookDirectDefer::PermissionNotice)?;
            let pending = json!({
                "cutover_complete": current["cutover_complete"].as_bool().unwrap_or(true),
                "generation": generation,
                "pending_generation": next_generation,
                "version": 1,
            });
            let lock_wait = remaining(deadline).min(QUESTION_LOCK_WAIT);
            let lock = policy_generation_lock::acquire(&resolved_home, lock_wait)
                .ok_or(HookDirectDefer::PermissionNotice)?;
            if secrets
                .set_secret(
                    &control_ref,
                    &serde_json::to_string(&pending)
                        .map_err(|_| HookDirectDefer::PermissionNotice)?,
                )
                .is_err()
            {
                drop(lock);
                return Err(HookDirectDefer::PermissionNotice);
            }
            save.insert("session_id".to_owned(), session_id.clone().into());
            save.insert("current_generation".to_owned(), generation.into());
            let save_request = authority_request(
                &store_path,
                &resolved_home,
                QUESTION_SAVE,
                &now,
                Some(&session_id),
                Some((&key_b64, &material.key_id)),
                Some(Value::Object(save.clone())),
                home_dir,
            )?;
            let saved =
                hook_authority_state_op::evaluate_within(&save_request, remaining(deadline))
                    .map_err(|_| HookDirectDefer::PermissionNotice)?;
            if saved.get("saved") != Some(&Value::Bool(true)) {
                drop(lock);
                return Err(HookDirectDefer::PermissionNotice);
            }
            let proposed = saved
                .get("next_control_state")
                .ok_or(HookDirectDefer::PermissionNotice)?;
            let finalized = finalization_state(Some(&pending), proposed)
                .ok_or(HookDirectDefer::PermissionNotice)?;
            secrets
                .set_secret(
                    &control_ref,
                    &serde_json::to_string(&finalized)
                        .map_err(|_| HookDirectDefer::PermissionNotice)?,
                )
                .map_err(|_| HookDirectDefer::PermissionNotice)?;
            drop(lock);
            let consume_request = authority_request(
                &store_path,
                &resolved_home,
                QUESTION_CONSUME,
                &now,
                Some(&session_id),
                Some((&key_b64, &material.key_id)),
                Some(Value::Object(save)),
                home_dir,
            )?;
            let consumed =
                hook_authority_state_op::evaluate_within(&consume_request, remaining(deadline))
                    .map_err(|_| HookDirectDefer::PermissionNotice)?;
            if consumed.get("consumed") == Some(&Value::Bool(true)) {
                Ok(Some(json!({})))
            } else {
                Err(HookDirectDefer::PermissionNotice)
            }
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn question_wire(payload: &Map<String, Value>) -> Option<String> {
    let tool_name = payload.get("tool_name")?.as_str()?;
    if python_strip(tool_name).ok()??.to_ascii_lowercase() != "askuserquestion" {
        return None;
    }
    serde_json::to_string(&json!({
        "event": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": payload.get("tool_input").cloned().unwrap_or(Value::Null),
        "tool_response": payload.get("tool_response").cloned().unwrap_or(Value::Null),
    }))
    .ok()
}

#[derive(Debug, PartialEq)]
enum QuestionSettlement {
    None,
    Answered,
    Save(Map<String, Value>),
}

fn settled_reply(reply: &Value) -> Result<QuestionSettlement, HookDirectDefer> {
    let fields = reply.as_object().ok_or(HookDirectDefer::PermissionNotice)?;
    let outcome = fields
        .get("outcome")
        .and_then(Value::as_str)
        .ok_or(HookDirectDefer::PermissionNotice)?;
    if matches!(outcome, "none" | "unseen" | "unanswered") && fields.len() == 1 {
        return Ok(if outcome == "none" {
            QuestionSettlement::None
        } else {
            QuestionSettlement::Answered
        });
    }
    let has_pending_id = fields.contains_key("pending_id");
    if outcome != "save"
        || fields.len() != 6 + usize::from(has_pending_id)
        || ![
            "artifact_id",
            "pending_artifact_hash",
            "reason",
            "source",
            "plan",
        ]
        .iter()
        .all(|name| fields.contains_key(*name))
        || (has_pending_id && fields["pending_id"].as_str().is_none_or(str::is_empty))
    {
        return Err(HookDirectDefer::PermissionNotice);
    }
    for name in ["artifact_id", "pending_artifact_hash", "reason", "source"] {
        if fields[name].as_str().is_none_or(str::is_empty) {
            return Err(HookDirectDefer::PermissionNotice);
        }
    }
    let mut save = fields.clone();
    save.remove("outcome");
    Ok(QuestionSettlement::Save(save))
}

fn authority_request(
    store_path: &Path,
    guard_home: &Path,
    op: &str,
    now: &str,
    session_id: Option<&str>,
    key: Option<(&str, &str)>,
    payload: Option<Value>,
    tilde_home: Option<&str>,
) -> Result<HookAuthorityStateRequestV1, HookDirectDefer> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| HookDirectDefer::PermissionNotice)?;
    let request_id = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut request = HookAuthorityStateRequestV1 {
        schema: HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.to_owned(),
        request_id: format!("hook-authority-state-{request_id}"),
        store_path: store_path.to_string_lossy().into_owned(),
        guard_home: guard_home.to_string_lossy().into_owned(),
        op: op.to_owned(),
        now: now.to_owned(),
        session_id: session_id.map(str::to_owned),
        payload,
        tilde_home: tilde_home.map(str::to_owned),
        ..HookAuthorityStateRequestV1::default()
    };
    if let Some((encoded, key_id)) = key {
        request.integrity_key_b64 = Some(encoded.to_owned());
        request.integrity_key_id = Some(key_id.to_owned());
    }
    if serde_json::to_vec(&request)
        .ok()
        .is_none_or(|bytes| bytes.len() > guard_contracts::HOOK_AUTHORITY_STATE_MAX_BYTES * 2)
    {
        return Err(HookDirectDefer::PermissionNotice);
    }
    Ok(request)
}

/// Whether `harness` only records, read as `hook_direct::answer` reads it:
/// its own posture first, then the snapshot mode. Watch leaves CIGAR resting
/// for a new session as it does for a prompt, and so does a binding whose
/// lease has lapsed.
pub(crate) fn records_only(harness: &str, policy_store: &PolicySnapshotStore) -> bool {
    let Ok(binding) = policy_store.admit_direct_binding() else {
        return true;
    };
    match binding
        .harness_postures
        .as_ref()
        .and_then(|postures| postures.get(harness))
    {
        Some(posture) => posture == "watch",
        None => match policy_store.current_admitted_snapshot() {
            Ok(snapshot) => snapshot.mode == "observe",
            Err(_) => true,
        },
    }
}

/// `claude_permission_request_response`. Without a session the daemon looks
/// up no notice and leaves the decision to Claude's own dialog.
fn claude_permission_answer(
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // `_optional_string(payload.get("session_id"))`.
    let session_id = match payload.get("session_id").and_then(Value::as_str) {
        Some(value) => python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?,
        None => None,
    };
    let Some(session_id) = session_id else {
        return Ok(json!({ "harness_response": permission_request_response(payload, None) }));
    };
    // Without a notice row `claude_load_notice` reads nothing it would
    // change, so only a session with one opens the store for writing.
    let present = crate::local_store_read::claude_permission_notice_present(
        Path::new(guard_home),
        session_id,
    )
    .map_err(|_| HookDirectDefer::PermissionNotice)?;
    if !present {
        return Ok(json!({ "harness_response": permission_request_response(payload, None) }));
    }
    // Only the daemon's key verifies a notice row, so a row, even one the
    // daemon would reject, takes the daemon path when the key is not bound.
    let binding = policy_store
        .admit_direct_binding()
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    let integrity_key = binding
        .integrity_key
        .as_ref()
        .ok_or(HookDirectDefer::PermissionNotice)?;
    let store_path = Path::new(guard_home).join("guard.db");
    // `datetime.now(timezone.utc).isoformat()`.
    let now = utc_now_isoformat().ok_or(HookDirectDefer::PermissionNotice)?;
    let tool_name = notification_tool_name(payload);
    let notice = claude_permission_notice_direct(
        &store_path,
        &integrity_key.key,
        &integrity_key.key_id,
        &now,
        session_id,
        tool_name.as_deref(),
    )
    .map_err(|_| HookDirectDefer::PermissionNotice)?;
    Ok(json!({ "harness_response": permission_request_response(payload, notice.as_ref()) }))
}

/// `_claude_permission_prompt_notification_response`.
fn claude_permission_prompt_answer(
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<Value, HookDirectDefer> {
    // The event copies these fields as the daemon parsed them. A number may
    // be spelled differently once Python reads it, and a nested value can
    // hold one, so only text, booleans and null are recorded here.
    if ["session_id", "tool_name"].iter().any(|field| {
        matches!(
            payload.get(*field),
            Some(Value::Number(_) | Value::Array(_) | Value::Object(_))
        )
    }) {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    let session_id = match payload.get("session_id").and_then(Value::as_str) {
        Some(value) => python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?,
        None => None,
    };
    // The event is written for every prompt, so every answer needs a
    // current binding. The key travels with that binding. The transaction
    // looks for a notice after it takes the write lock, so a notice that
    // lands in between cannot be answered without being marked seen.
    let binding = policy_store
        .admit_direct_binding()
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    let key = binding
        .integrity_key
        .as_ref()
        .map(|integrity_key| (&integrity_key.key[..], integrity_key.key_id.as_str()));
    let store_path = Path::new(guard_home).join("guard.db");
    let now = utc_now_isoformat().ok_or(HookDirectDefer::PermissionNotice)?;
    let tool_name = notification_tool_name(payload);
    let render = |notice: Option<&Map<String, Value>>| permission_prompt_event(payload, notice);
    let notice = claude_permission_prompt_direct(
        &store_path,
        key,
        &now,
        session_id,
        tool_name.as_deref(),
        (PERMISSION_PROMPT_EVENT, &render),
    )
    .map_err(|_| HookDirectDefer::PermissionNotice)?;
    Ok(json!({
        "harness_response": permission_prompt_notification_response(payload, notice.as_ref()),
    }))
}

/// `claude_turn_stop`, which the daemon runs before it answers `Stop` with
/// its constant.
fn claude_turn_stop_answer(
    guard_home: &str,
    payload: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
) -> Result<(), HookDirectDefer> {
    // The event records the session as the daemon parsed it, and Python may
    // spell a number differently, so only text and null are recorded here.
    if matches!(
        payload.get("session_id"),
        Some(Value::Number(_) | Value::Array(_) | Value::Object(_))
    ) {
        return Err(HookDirectDefer::PayloadUnsupported);
    }
    let session_id = match payload.get("session_id").and_then(Value::as_str) {
        Some(value) => python_strip(value).map_err(|_| HookDirectDefer::EventUnsupported)?,
        None => None,
    };
    let binding = policy_store
        .admit_direct_binding()
        .map_err(|_| HookDirectDefer::PermissionNotice)?;
    let key = binding
        .integrity_key
        .as_ref()
        .map(|integrity_key| (&integrity_key.key[..], integrity_key.key_id.as_str()));
    let store_path = Path::new(guard_home).join("guard.db");
    let now = utc_now_isoformat().ok_or(HookDirectDefer::PermissionNotice)?;
    claude_turn_stop_direct(&store_path, key, &now, session_id, payload)
        .map_err(|_| HookDirectDefer::PermissionNotice)
}

pub(crate) fn utc_now_isoformat() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")
}
