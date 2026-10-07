//! Canonical request/result contracts for the `PromptAnalyze` resident op
//! (RTM-019). One subop-multiplexed op covering the runner prompt-analysis
//! helpers ported into `guard_command::guard_run_launch`:
//!
//!   * `extract`                — `extract_prompt_requests`
//!   * `detect_injection`       — `detect_prompt_injection_requests`
//!   * `to_artifacts`           — `prompt_requests_to_artifacts`
//!   * `should_force_reapproval`— `should_force_reapproval`
//!   * `request_id`             — `prompt_request_id`
//!
//! `deny_unknown_fields` prevents a stale resident from smuggling new keys
//! past the schema check.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Single feature token for the whole prompt-analysis surface.
pub const PROMPT_ANALYZE_FEATURE: &str = "prompt-analyze-v1";
pub const PROMPT_ANALYZE_REQUEST_SCHEMA: &str = "guard-prompt-analyze-request.v1";
pub const PROMPT_ANALYZE_RESULT_SCHEMA: &str = "guard-prompt-analyze-result.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptAnalyzeRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// `extract` | `detect_injection` | `to_artifacts` |
    /// `should_force_reapproval` | `request_id`.
    pub subop: String,
    /// `extract`/`detect_injection`/`request_id`: the raw prompt text.
    pub prompt_text: Option<String>,
    /// `request_id`: request class + matched text.
    pub request_class: Option<String>,
    pub matched_text: Option<String>,
    /// `to_artifacts`: harness + config path.
    pub harness: Option<String>,
    pub config_path: Option<String>,
    /// `to_artifacts`/`should_force_reapproval`: serialized
    /// `GuardRunPromptRequest.to_dict()` objects.
    pub requests: Option<Vec<Value>>,
    /// `should_force_reapproval`: whether a prior policy existed.
    pub prior_policy_present: Option<bool>,
    /// `should_force_reapproval`: approved prompt classes.
    pub approved_classes: Option<Vec<String>>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptAnalyzeResultV1 {
    pub schema: String,
    /// Subop payload: array of request dicts (`extract`/`detect_injection`),
    /// array of artifact dicts (`to_artifacts`), bool
    /// (`should_force_reapproval`), or string (`request_id`). `None` when the
    /// subop could not run (caller falls back to Python).
    pub result: Option<Value>,
}
