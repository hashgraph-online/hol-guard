//! `HookDecide` `claude_permission_verdict` — wire contract for the verdict
//! the CLI hook gives Claude Code's permission dialog (`PermissionRequest`).
//!
//! The transport peeks the session's pending Guard notice, marks it seen and
//! sends it here with whether a runtime artifact was found. The resident picks
//! the verdict: no decision (Claude keeps its own dialog), the Guard approval
//! question, a review that defers to Claude's dialog, or a deny. When the
//! verdict depends on the artifact's policy, the resident asks for those facts
//! by name and the transport resubmits with them. The transport only renders
//! the host response for the verdict it is given; a verdict it cannot read is
//! no verdict, and the caller answers with the host outage response.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Advertised when the resident answers `claude_permission_verdict`; a
/// resident that predates it rejects the query.
pub const HOOK_DECISION_CLAUDE_PERMISSION_VERDICT_FEATURE: &str =
    "hook-decision-claude-permission-verdict-v1";

/// The fact the resident asks for when the verdict rests on the runtime
/// artifact's policy.
pub const CLAUDE_PERMISSION_ARTIFACT_POLICY_FACT: &str = "artifact_policy";

/// Facts Claude's permission-dialog verdict depends on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaudePermissionVerdictInputsV1 {
    /// The session's pending Guard notice for this dialog, as the store
    /// returned it; `None` when there is none.
    pub notice: Option<Map<String, Value>>,
    /// The transport resolved a runtime artifact for the dialog's tool call.
    pub runtime_artifact_present: bool,
    /// The runtime artifact's policy, sent only once the resident asks for
    /// `artifact_policy`.
    #[serde(default)]
    pub artifact_policy: Option<ClaudePermissionArtifactPolicyV1>,
}

/// The runtime artifact's policy facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaudePermissionArtifactPolicyV1 {
    /// The configured action for the artifact, as the resident composed it.
    pub config_action: String,
    /// The package evaluation's action for a package request; `None` for any
    /// other artifact.
    pub package_action: Option<String>,
}

/// The verdict for Claude's permission dialog and what its response carries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClaudePermissionVerdictV1 {
    /// `passthrough` (no decision: Claude keeps its own dialog),
    /// `guard_question` (Claude's dialog is denied and Claude is sent to the
    /// Guard approval question), `review` (the review reason is shown and
    /// Claude's dialog decides) or `deny`.
    pub verdict: String,
    /// The action the host response renders; `None` for `passthrough`.
    pub policy_action: Option<String>,
    /// The response offers the user a way to approve the call: Claude's own
    /// dialog for `review`, the Guard approval question for `guard_question`.
    pub offers_approval: bool,
    /// The response's reason. When `reason_from_artifact` is set it is used
    /// only if the artifact's own reason renders blank.
    pub reason: Option<String>,
    /// The reason is rendered from the runtime artifact.
    pub reason_from_artifact: bool,
    /// The artifact's composed policy action, which its reason is rendered
    /// with; `None` unless `reason_from_artifact` is set.
    pub artifact_action: Option<String>,
}
