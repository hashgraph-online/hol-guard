//! `HookDecide` `silent_review_block` and `paused_review` — the response a
//! native PreToolUse review shows the agent.
//!
//! A paused review is the prompted pause with the signed review link in its
//! reason. A silent review is the block the agent sees when the user is not
//! asked.
//!
//! The daemon queues the review (or fails to) and looks up the connector that
//! ran the call; this composes everything the agent reads from there:
//!
//! * the reason: the connector's setup text when the review was queued with
//!   one, else the safe-alternative text for the native reason and code;
//! * the read-only wait hint, when the identical retry reuses an approval;
//! * the review link, only when an approval can unblock the action and the
//!   user is asked, no setup text applies, or the connector is a local one;
//! * the rendered `safe-alternative` response, never prompted, with the
//!   `approval_resume` handle a bound retry can watch.
//!
//! The approval invariant is untouched: this renders a block the agent sees,
//! and the queued row keeps whatever choices its binding offers. A malformed
//! query is an error the transport fails closed on, never a default block.

use std::path::Path;

use guard_command::hook_responses::{pre_tool_review, Object};
use guard_contracts::{
    PausedReviewInputsV1, PausedReviewV1, SilentReviewBlockInputsV1, SilentReviewBlockV1,
};
use serde_json::{json, Value};

use crate::blocked_request_mode::{
    approval_wait_hint_for_home, falsy_or_text, safe_alternative_block,
    safe_alternative_reason_with_retry, BLOCKED_REASON,
};
use crate::guard_store_json::py_strip;
use crate::native_review_link::{
    canonical_harness, native_review_reason, now_micros, without_raw_url, SIGNED_LINK_UNAVAILABLE,
};

const INVALID: &str = "native_hook_decision_payload_invalid";
/// The reason a paused review shows when its verdict carries none.
pub(crate) const REVIEW_DEFAULT_REASON: &str =
    "HOL Guard requires review before this action can execute.";

pub(crate) fn silent_review_block(
    inputs: &SilentReviewBlockInputsV1,
) -> Result<SilentReviewBlockV1, String> {
    respond(inputs, |harness, reason, url| {
        signed_review_reason(&inputs.guard_home, harness, reason, url)
    })
}

pub(crate) fn paused_review(inputs: &PausedReviewInputsV1) -> PausedReviewV1 {
    pause(inputs, |harness, reason, url| {
        signed_review_reason(&inputs.guard_home, harness, reason, url)
    })
}

/// `native_review_reason` with the daemon token of `guard_home` and the clock.
fn signed_review_reason(
    guard_home: &str,
    harness: &str,
    reason: &str,
    url: &str,
) -> Option<String> {
    let auth_token =
        crate::daemon_policy_authority::load_guard_daemon_auth_token(Path::new(guard_home));
    native_review_reason(harness, reason, url, auth_token.as_deref(), now_micros()?)
}

/// The paused review for `inputs`; `link` is `native_review_reason` with the
/// daemon token and clock already bound. A link shape the resident cannot sign
/// leaves no raw URL in the reason; the queued row is still in the inbox.
fn pause(
    inputs: &PausedReviewInputsV1,
    link: impl FnOnce(&str, &str, &str) -> Option<String>,
) -> PausedReviewV1 {
    let url = inputs
        .approval
        .as_ref()
        .and_then(|approval| approval.get("approval_url"))
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|url| !url.is_empty());
    let reason = match inputs.verdict.get("reason") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => REVIEW_DEFAULT_REASON,
    };
    let linked = url.and_then(|url| {
        link(&canonical_harness(&inputs.harness), reason, url).or_else(|| {
            // The resident could not reproduce or sign this link shape, so the
            // agent reads the reason without a raw URL it cannot act on.
            Some(
                py_strip(&format!(
                    "{} {SIGNED_LINK_UNAVAILABLE}",
                    without_raw_url(reason, url)
                ))
                .to_owned(),
            )
        })
    });
    PausedReviewV1 {
        response: pre_tool_review(
            &inputs.harness,
            &inputs.verdict,
            inputs.approval.as_ref(),
            linked.as_deref(),
        ),
    }
}

/// The response for `inputs`; `link` is `native_review_reason` with the
/// daemon token and clock already bound.
fn respond(
    inputs: &SilentReviewBlockInputsV1,
    link: impl FnOnce(&str, &str, &str) -> Option<String>,
) -> Result<SilentReviewBlockV1, String> {
    let result: &Object = &inputs.result;
    // A review that never reached the inbox has no setup row to point at.
    let setup = inputs.setup_reason.as_deref().filter(|_| inputs.queued);
    let mut reason = match setup.filter(|text| !text.is_empty()) {
        Some(text) => text.to_owned(),
        None => {
            let reason = falsy_or_text(result.get("reason"), BLOCKED_REASON).ok_or(INVALID)?;
            let code = falsy_or_text(result.get("reason_code"), "").ok_or(INVALID)?;
            safe_alternative_reason_with_retry(
                reason,
                Some(if code.is_empty() { "unknown" } else { code }),
                Some(inputs.queued),
                inputs.retry_reuses_approval,
                inputs.exact_action_allowable,
            )
        }
    };
    // Approving a row that is neither bound to the retry nor eligible for an
    // exact-action Always cannot let the agent run the action, so the reason
    // does not send the user to approve it; nor does a remote connector's
    // setup reason in the default mode.
    let approval_can_unblock = inputs.retry_reuses_approval || inputs.exact_action_allowable;
    let links =
        approval_can_unblock && (inputs.ask || setup.is_none() || inputs.connector_is_local);
    let request_id = inputs.request_id.as_deref().filter(|_| inputs.queued);
    if let Some(id) = request_id.filter(|_| inputs.retry_reuses_approval) {
        let hint = approval_wait_hint_for_home(id, &inputs.guard_home, &inputs.home_dir);
        reason = py_strip(&format!("{reason} {hint}")).to_owned();
    }
    let url = inputs
        .approval_url
        .as_deref()
        .filter(|_| inputs.queued && links)
        .map(py_strip)
        .filter(|url| !url.is_empty());
    if let Some(url) = url {
        // A link shape the resident cannot sign leaves no raw URL behind, as
        // the direct lane does once a request is queued.
        reason = match link(&canonical_harness(&inputs.harness), &reason, url) {
            Some(linked) => linked,
            None => py_strip(&format!(
                "{} {SIGNED_LINK_UNAVAILABLE}",
                without_raw_url(&reason, url)
            ))
            .to_owned(),
        };
    }
    let mut response = safe_alternative_block(&inputs.harness, result, &reason);
    if let Some(id) = request_id.filter(|id| inputs.retry_reuses_approval && !id.is_empty()) {
        response.insert(
            "approval_resume".to_owned(),
            json!({"request_id": id, "poll_path": format!("/v1/requests/{id}")}),
        );
    }
    Ok(SilentReviewBlockV1 { response })
}

#[cfg(test)]
#[path = "hook_decision_review_response_tests.rs"]
mod tests;
