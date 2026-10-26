//! `extension_review_hint` -- the extension hints for a review the daemon
//! queues, and for a pending review that reaches the inbox without them.
//!
//! The direct hook lane stores its own hints ([`super::settle`]). A review the
//! lane hands back to the daemon is queued there, and the daemon asks this op
//! for the same hints instead of reviewing the command again itself:
//!
//! - With the paused result (`paused`), it answers what the direct lane would
//!   have stored: the coverage hint read out of the paused evidence, and the
//!   allow hint when the fresh review is exactly the one that paused.
//! - Without it, for a pending row read back with nothing settled, it reviews
//!   the command once under the admitted snapshot and answers both hints from
//!   that review.
//!
//! Both answer under the controls the resident admitted and never mutate
//! authority. The hints are advisory: a review that cannot be bound, a budget
//! that runs out or a missing snapshot answers less, never an error the
//! review depends on.

use std::time::{Duration, Instant};

use guard_command::native_command_controls::CompiledNativeCommandControls;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::super::review_request::allow_hint_candidate;
use super::super::HintScope;
use super::{counterfactual, coverage_hint, remaining, settled, shell_review, MIN_BUDGET};
use crate::extension_coverage_hint::{compute, with_coverage};
use crate::oneshot::PreToolRequestV1;
use crate::package_authority_op::request_digest_with_limit;
use crate::policy_store::PolicySnapshotStore;

pub(crate) const EXTENSION_REVIEW_HINT_FEATURE: &str = "extension-review-hint-v1";
const REQUEST_SCHEMA: &str = "guard-extension-review-hint-request.v1";
const RESULT_SCHEMA: &str = "guard-extension-review-hint-result.v1";
const QUERY_KIND: &str = "review_hint";
/// The canonical request bound; the daemon never sends a larger one.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// The most a caller can hand the hints, whatever its own deadline says.
const MAX_BUDGET_MS: u32 = 10_000;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtensionReviewHintRequestV1 {
    schema: String,
    #[serde(default)]
    request_id: String,
    query: ReviewHintQueryV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewHintQueryV1 {
    kind: String,
    /// The hook payload, or a command-only payload for a pending row.
    payload: Map<String, Value>,
    /// The launch directory used when the payload names none; empty for none.
    workspace: String,
    /// The home the command runs under; empty for none.
    home_dir: String,
    /// The result the review paused on, for a review being queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paused: Option<Map<String, Value>>,
    /// Milliseconds the caller can wait for the answer.
    budget_ms: u32,
}

#[derive(Serialize)]
struct ResultV1<'a> {
    schema: &'static str,
    request_id: &'a str,
    request_sha256: String,
    /// `ok` or `error`.
    status: &'static str,
    /// `ok`, or one of the `native_extension_review_hint_*` failure codes.
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<PayloadV1>,
}

#[derive(Serialize)]
struct PayloadV1 {
    kind: &'static str,
    hint: Option<Value>,
}

pub(crate) fn evaluate_with_store(
    request: &ExtensionReviewHintRequestV1,
    store: Option<&PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any review; an oversized
    // request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, MAX_REQUEST_BYTES)
        .map_err(|_| "native_extension_review_hint_too_large".to_owned())?;
    let (status, code, payload) = match decide(request, store) {
        Ok(hint) => (
            "ok",
            "ok".to_owned(),
            Some(PayloadV1 {
                kind: QUERY_KIND,
                hint,
            }),
        ),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&ResultV1 {
        schema: RESULT_SCHEMA,
        request_id: &request.request_id,
        request_sha256,
        status,
        code,
        payload,
    })
}

fn decide(
    request: &ExtensionReviewHintRequestV1,
    store: Option<&PolicySnapshotStore>,
) -> Result<Option<Value>, String> {
    if request.schema != REQUEST_SCHEMA {
        return Err("native_extension_review_hint_schema_mismatch".to_owned());
    }
    let query = &request.query;
    if query.kind != QUERY_KIND {
        return Err("native_extension_review_hint_kind_invalid".to_owned());
    }
    let budget = Duration::from_millis(u64::from(query.budget_ms.min(MAX_BUDGET_MS)));
    let deadline = Instant::now() + budget;
    Ok(match &query.paused {
        Some(paused) => queued(store, query, paused, deadline),
        None => live(store, query, deadline),
    })
}

/// `native_review_hint` for a review the daemon queues: the coverage hint the
/// paused evidence carries, with the allow hint when an extension Allow would
/// settle exactly this pause.
fn queued(
    store: Option<&PolicySnapshotStore>,
    query: &ReviewHintQueryV1,
    paused: &Map<String, Value>,
    deadline: Instant,
) -> Option<Value> {
    let request = json!({ "extension_allow_hint": coverage_hint(paused) });
    let request = match store {
        Some(policy_store) => settled(
            Some(&HintScope {
                policy_store,
                deadline,
            }),
            &query.payload,
            &query.workspace,
            &query.home_dir,
            paused,
            request,
        ),
        None => request,
    };
    request
        .get("extension_allow_hint")
        .filter(|hint| !hint.is_null())
        .cloned()
}

/// `live_approval_extension_hint`: one review of a pending command under the
/// admitted snapshot, answering both hints from it.
fn live(
    store: Option<&PolicySnapshotStore>,
    query: &ReviewHintQueryV1,
    deadline: Instant,
) -> Option<Value> {
    if remaining(deadline)? < MIN_BUDGET {
        return None;
    }
    let review = shell_review(&query.payload, &query.workspace, &query.home_dir)?;
    crate::command_effect::with_store(store, |controls| {
        // Without admitted extension controls there is nothing to recommend.
        Ok(controls.and_then(|controls| live_under(controls, &query.payload, &review, deadline)))
    })
    .ok()
    .flatten()
}

fn live_under(
    controls: &CompiledNativeCommandControls,
    payload: &Map<String, Value>,
    review: &PreToolRequestV1,
    deadline: Instant,
) -> Option<Value> {
    let fresh =
        crate::pre_tool_extension_evidence_op::evidence_response(review, Some(controls)).ok()?;
    let reviewed = fresh.as_object()?;
    let coverage = compute(reviewed);
    // The allow hint is the queue-time one, gated the same way, but bound to
    // the review run here: the row keeps no paused result to compare with.
    let allow = if allow_hint_candidate(payload, reviewed) == Some(true) {
        counterfactual(controls, review, fresh.clone(), deadline)
            .ok()
            .flatten()
            .and_then(|hint| serde_json::to_value(hint).ok())
    } else {
        None
    };
    with_coverage(allow, coverage)
}

#[cfg(test)]
#[path = "hook_direct_review_hint_op_tests.rs"]
mod tests;
