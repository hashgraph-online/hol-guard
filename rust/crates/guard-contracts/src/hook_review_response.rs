//! `HookDecide` `silent_review_block` and `paused_review` — wire contracts
//! for the response a native PreToolUse review shows the agent.
//!
//! The transport has already queued the review (or failed to) and looked up
//! the connector that ran the call. It sends those facts; the resident
//! composes the agent-facing reason (the safe-alternative text or the
//! connector's setup text, the approval wait hint and the signed review link)
//! and answers with the final rendered PreToolUse response. No answer is a
//! resident outage the transport fails closed on.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Advertised when the resident answers `silent_review_block` and
/// `paused_review`; a resident that predates it rejects both queries.
pub const HOOK_DECISION_REVIEW_RESPONSE_FEATURE: &str = "hook-decision-review-response-v1";

/// Facts the silent review block depends on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SilentReviewBlockInputsV1 {
    /// The harness the response is rendered for, as the hook names it.
    pub harness: String,
    /// The native PreToolUse result being blocked.
    pub result: Map<String, Value>,
    /// The connector's agent-facing setup text, when a connector applies. It
    /// is used only when the review was queued.
    pub setup_reason: Option<String>,
    /// The review reached the approval inbox.
    pub queued: bool,
    /// The queued review's request id, when it is text.
    pub request_id: Option<String>,
    /// The queued review's approval URL, when it is text.
    pub approval_url: Option<String>,
    /// Blocked requests are offered for approval (`blocked_request_mode`).
    pub ask: bool,
    /// The agent's retry reuses an approval (a retry binding exists).
    pub retry_reuses_approval: bool,
    /// An exact-action token exists, so Always allow can answer the action.
    pub exact_action_allowable: bool,
    /// The connector that ran the call is a local surface.
    pub connector_is_local: bool,
    /// The Guard home the review was queued in.
    pub guard_home: String,
    /// The user's home directory.
    pub home_dir: String,
}

/// The final PreToolUse response the hook returns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SilentReviewBlockV1 {
    pub response: Map<String, Value>,
}

/// Facts a paused (prompted) review renders from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PausedReviewInputsV1 {
    /// The harness the response is rendered for, as the hook names it.
    pub harness: String,
    /// The review verdict, with any connector setup text already in `reason`.
    pub verdict: Map<String, Value>,
    /// The queued review's `approval_url` and `request_id`, when queued.
    pub approval: Option<Map<String, Value>>,
    /// The Guard home the review was queued in.
    pub guard_home: String,
}

/// The paused PreToolUse response the hook returns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PausedReviewV1 {
    pub response: Map<String, Value>,
}
