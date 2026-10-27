//! Whether a live Codex allow may complete, and what it may claim.
//!
//! A Codex approval that was answered in the approval centre is finished by a
//! second request carrying the hook payload again. That payload is the agent's
//! word for what it is about to run, so the allow is only honoured when the
//! payload still names the action the user approved and a fresh review of it
//! still allows it. Both halves of that question are decided here: the caller
//! reads the rows and rebuilds the envelope, and runs the review between the
//! two queries because the reviewer re-enters its own hook pipeline.
//!
//! Both queries fail closed. Anything missing, malformed or mismatched denies
//! the completion rather than letting it through unreviewed.

use guard_contracts::{CodexLiveAllowPrecheckQueryV1, CodexLiveAllowSettleQueryV1};
use serde_json::{json, Map, Value};

use crate::guard_store_receipt_envelope::envelope_action_hash;

/// The statuses a resume row may carry for an allow it has already delivered.
const REPLAYABLE: [&str; 2] = ["resumed", "sent"];

pub(crate) fn codex_live_allow_precheck(query: &CodexLiveAllowPrecheckQueryV1) -> Value {
    let (claimed_hash, claimed_request_id) = claimed_allow(query);
    let review_required = review_required(query, &claimed_hash, &claimed_request_id);
    json!({
        "review_required": review_required,
        "claimed_saved_allow_hash": claimed_hash.map_or(Value::Null, Value::String),
        "claimed_approval_request_id": claimed_request_id.map_or(Value::Null, Value::String),
    })
}

pub(crate) fn codex_live_allow_settle(query: &CodexLiveAllowSettleQueryV1) -> Value {
    json!({"fresh_allow_authorized": fresh_allow_authorized(&query.fresh_review)})
}

/// The saved allow a fresh review of this request may claim.
///
/// A request the store still holds live authority for claims the allow under
/// the id the live decision arrived with. A terminal replay of an allow the
/// user already received claims the one the row itself records. Anything else
/// claims nothing, so the review has to find its own approval.
fn claimed_allow(query: &CodexLiveAllowPrecheckQueryV1) -> (Option<String>, Option<String>) {
    if text(&query.resolution_action) != Some("allow") {
        return (None, None);
    }
    let artifact_hash = nonempty(&query.artifact_hash);
    if query.authority_resolved {
        if let Some(artifact_hash) = artifact_hash.clone() {
            return (
                Some(artifact_hash),
                Some(text(&query.request_id).unwrap_or_default().to_owned()),
            );
        }
    }
    let replayable = text(&query.previous_resolution_action) == Some("allow")
        && text(&query.previous_status).is_some_and(|status| REPLAYABLE.contains(&status));
    if !replayable {
        return (None, None);
    }
    match (artifact_hash, nonempty(&query.row_request_id)) {
        (Some(artifact_hash), Some(request_id)) => (Some(artifact_hash), Some(request_id)),
        _ => (None, None),
    }
}

/// Whether the payload still names the action the stored allow was given for.
///
/// The envelope the caller rebuilt is compared with the stored one as it was
/// persisted. A payload that differs only in fields the action identity does
/// not cover still names the same action, but only a request that already
/// claims its own saved allow may rest on that weaker comparison.
fn review_required(
    query: &CodexLiveAllowPrecheckQueryV1,
    claimed_hash: &Option<String>,
    claimed_request_id: &Option<String>,
) -> bool {
    if text(&query.resolution_action) != Some("allow") {
        return false;
    }
    if text(&query.hook_event_name) != Some("PreToolUse") {
        return false;
    }
    let Some(fresh) = query.fresh_envelope.as_object() else {
        return false;
    };
    if query.fresh_envelope == query.stored_envelope {
        return true;
    }
    let claimed_hash = claimed_hash.as_deref().filter(|found| !found.is_empty());
    let claimed_request_id = claimed_request_id
        .as_deref()
        .filter(|found| !found.is_empty());
    let (Some(stored), Some(claimed_hash), Some(claimed_request_id)) = (
        query.stored_envelope.as_object(),
        claimed_hash,
        claimed_request_id,
    ) else {
        return false;
    };
    if text(&query.artifact_hash) != Some(claimed_hash)
        || text(&query.row_request_id) != Some(claimed_request_id)
    {
        return false;
    }
    matching_action(fresh, stored)
}

fn matching_action(fresh: &Map<String, Value>, stored: &Map<String, Value>) -> bool {
    match (envelope_action_hash(fresh), envelope_action_hash(stored)) {
        (Some(fresh), Some(stored)) => fresh == stored,
        _ => false,
    }
}

/// A review that reported no `PreToolUse` allow leaves the request denied.
///
/// An empty answer is the hook pipeline's "nothing to say about this": there
/// is no decision to disagree with, so the stored allow stands.
fn fresh_allow_authorized(fresh_review: &Value) -> bool {
    let Some(review) = fresh_review.as_object() else {
        return false;
    };
    if review.is_empty() {
        return true;
    }
    let Some(output) = review.get("hookSpecificOutput").and_then(Value::as_object) else {
        return false;
    };
    if output.get("hookEventName").and_then(Value::as_str) != Some("PreToolUse") {
        return false;
    }
    match output.get("permissionDecision") {
        None | Some(Value::Null) => true,
        Some(decision) => decision.as_str() == Some("allow"),
    }
}

fn text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn nonempty(value: &Value) -> Option<String> {
    text(value)
        .filter(|found| !found.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(command: &str) -> Value {
        json!({
            "schema_version": 1,
            "action_id": "",
            "harness": "codex",
            "event_name": "PreToolUse",
            "action_type": "shell_command",
            "command": command,
            "target_paths": [],
            "network_hosts": [],
            "package_targets": [],
            "raw_payload_redacted": {},
        })
    }

    fn query(stored: Value, fresh: Value) -> CodexLiveAllowPrecheckQueryV1 {
        CodexLiveAllowPrecheckQueryV1 {
            resolution_action: json!("allow"),
            artifact_hash: json!("hash-1"),
            row_request_id: json!("req-1"),
            stored_envelope: stored,
            previous_resolution_action: Value::Null,
            previous_status: Value::Null,
            request_id: json!("req-1"),
            authority_resolved: false,
            hook_event_name: json!("PreToolUse"),
            fresh_envelope: fresh,
        }
    }

    fn changed_payload() -> Value {
        let mut stored = envelope("ls");
        stored["prompt_text"] = json!("the prompt the approval was recorded under");
        stored
    }

    #[test]
    fn an_unchanged_envelope_is_reviewed_without_claiming_an_allow() {
        let answer = codex_live_allow_precheck(&query(envelope("ls"), envelope("ls")));
        assert_eq!(answer["review_required"], json!(true));
        assert_eq!(answer["claimed_saved_allow_hash"], Value::Null);
        assert_eq!(answer["claimed_approval_request_id"], Value::Null);
    }

    #[test]
    fn a_different_action_is_refused_even_with_a_claim() {
        let mut live = query(envelope("ls"), envelope("rm -rf /"));
        live.authority_resolved = true;
        let answer = codex_live_allow_precheck(&live);
        assert_eq!(answer["review_required"], json!(false));
        assert_eq!(answer["claimed_saved_allow_hash"], json!("hash-1"));
    }

    #[test]
    fn the_same_action_under_a_changed_payload_needs_a_claim() {
        let unclaimed = codex_live_allow_precheck(&query(changed_payload(), envelope("ls")));
        assert_eq!(unclaimed["review_required"], json!(false));

        let mut live = query(changed_payload(), envelope("ls"));
        live.authority_resolved = true;
        let claimed = codex_live_allow_precheck(&live);
        assert_eq!(claimed["review_required"], json!(true));
        assert_eq!(claimed["claimed_approval_request_id"], json!("req-1"));
    }

    #[test]
    fn a_terminal_allow_replay_claims_the_rows_own_request() {
        let mut replay = query(changed_payload(), envelope("ls"));
        replay.previous_resolution_action = json!("allow");
        replay.previous_status = json!("resumed");
        let answer = codex_live_allow_precheck(&replay);
        assert_eq!(answer["review_required"], json!(true));
        assert_eq!(answer["claimed_saved_allow_hash"], json!("hash-1"));

        replay.previous_status = json!("pending");
        let answer = codex_live_allow_precheck(&replay);
        assert_eq!(answer["review_required"], json!(false));
        assert_eq!(answer["claimed_saved_allow_hash"], Value::Null);
    }

    #[test]
    fn a_request_that_was_not_allowed_is_never_revalidated() {
        let mut denied = query(envelope("ls"), envelope("ls"));
        denied.resolution_action = json!("deny");
        denied.authority_resolved = true;
        let answer = codex_live_allow_precheck(&denied);
        assert_eq!(answer["review_required"], json!(false));
        assert_eq!(answer["claimed_saved_allow_hash"], Value::Null);
    }

    #[test]
    fn an_absent_row_or_payload_is_refused() {
        let mut missing = query(envelope("ls"), envelope("ls"));
        missing.resolution_action = Value::Null;
        assert_eq!(
            codex_live_allow_precheck(&missing)["review_required"],
            json!(false)
        );

        let mut unbuilt = query(envelope("ls"), Value::Null);
        unbuilt.authority_resolved = true;
        assert_eq!(
            codex_live_allow_precheck(&unbuilt)["review_required"],
            json!(false)
        );
    }

    #[test]
    fn a_payload_for_another_event_is_refused() {
        let mut other = query(envelope("ls"), envelope("ls"));
        other.hook_event_name = json!("PostToolUse");
        assert_eq!(
            codex_live_allow_precheck(&other)["review_required"],
            json!(false)
        );
    }

    #[test]
    fn a_malformed_stored_envelope_cannot_be_matched() {
        let mut stored = changed_payload();
        stored["policy_action"] = json!("allow");
        let mut live = query(stored, envelope("ls"));
        live.authority_resolved = true;
        assert_eq!(
            codex_live_allow_precheck(&live)["review_required"],
            json!(false)
        );
    }

    fn settled(review: Value) -> bool {
        codex_live_allow_settle(&CodexLiveAllowSettleQueryV1 {
            fresh_review: review,
        })["fresh_allow_authorized"]
            == json!(true)
    }

    #[test]
    fn only_a_pretooluse_allow_authorizes_the_completion() {
        assert!(settled(json!({})));
        assert!(settled(json!({
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}
        })));
        assert!(settled(json!({
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}
        })));
        assert!(settled(json!({
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": null}
        })));
        assert!(!settled(json!({
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}
        })));
        assert!(!settled(json!({
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "permissionDecision": "allow"}
        })));
        assert!(!settled(json!({"decision": "allow"})));
        assert!(!settled(Value::Null));
    }
}
