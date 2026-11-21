//! The skill workflow preflight contract.
//!
//! Two pure subops over one request. `dependencies` reads the
//! `hol-guard.dependencies` declaration a skill's frontmatter carries and
//! says whether it is absent, declared or invalid. `preflight` resolves a
//! declaration against the local CLI connections the caller observed and
//! says what a live runtime check would still have to establish.
//!
//! Neither touches the store, so the caller ships what it read: the raw
//! declaration text for the first, and the saved rows unchanged for the
//! second. The rows stay `Value` rather than narrowed types so the resident
//! compares them the way the store wrote them instead of inheriting a
//! judgement the caller already made.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Request schema for the skill workflow preflight op.
pub const SKILL_WORKFLOW_PREFLIGHT_REQUEST_SCHEMA: &str =
    "guard-skill-workflow-preflight-request.v1";
/// Result schema for the skill workflow preflight op.
pub const SKILL_WORKFLOW_PREFLIGHT_RESULT_SCHEMA: &str = "guard-skill-workflow-preflight-result.v1";
/// Feature string the resident advertises when it carries this op.
pub const SKILL_WORKFLOW_PREFLIGHT_FEATURE: &str = "skill-workflow-preflight-v1";
/// Largest request the op will read, in canonical bytes.
pub const SKILL_WORKFLOW_PREFLIGHT_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Require the field to be present, even when its value is null.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// The declaration as the frontmatter carried it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillDependenciesInputV1 {
    /// Whether the frontmatter carried the key with a non-null value.
    pub present: bool,
    /// The declaration text, or null when the value was not text Guard can
    /// put on the wire. A key that is there but unreadable is not a skill
    /// that declared nothing.
    #[serde(deserialize_with = "required")]
    pub text: Option<String>, // NOSONAR: rust:S9334; required key, nullable value.
}

/// A declaration and the authority it is resolved against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPreflightInputV1 {
    /// The declaration document, as `dependencies` returned it.
    pub dependencies: Value,
    /// The saved local CLI rows, unchanged.
    pub connections: Vec<Value>,
    /// The authority revision those rows were read at.
    pub authority_revision: i64,
}

/// One skill workflow preflight request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillWorkflowPreflightRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub subop: String,
    #[serde(deserialize_with = "required")]
    pub dependencies: Option<SkillDependenciesInputV1>, // NOSONAR: rust:S9334; required key, nullable value.
    #[serde(deserialize_with = "required")]
    pub preflight: Option<SkillPreflightInputV1>, // NOSONAR: rust:S9334; required key, nullable value.
}

/// One skill workflow preflight result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillWorkflowPreflightResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
