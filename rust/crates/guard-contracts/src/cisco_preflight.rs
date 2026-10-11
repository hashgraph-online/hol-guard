//! `CiscoPreflight` - wire contract for the resident op that owns the
//! authority half of the Cisco scanner preflight: which scan roots an action
//! may reach, the containment verdict for every target, the mapping of scanner
//! findings to runtime risk signals, and the policy action those signals
//! resolve to.
//!
//! The third-party analyzers themselves are not part of this contract: Python
//! runs them in a bounded subprocess between the `plan` and `evidence`
//! queries and hands back only what they reported. Python never recomputes a
//! verdict, a scan root or a signal.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CISCO_PREFLIGHT_REQUEST_SCHEMA: &str = "guard-cisco-preflight-request.v1";
/// Schema discriminator for the result.
pub const CISCO_PREFLIGHT_RESULT_SCHEMA: &str = "guard-cisco-preflight-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CISCO_PREFLIGHT_FEATURE: &str = "cisco-preflight-v1";
/// Largest canonical request serialization the op will accept.
pub const CISCO_PREFLIGHT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most targets, steps or findings one request may carry.
pub const CISCO_PREFLIGHT_MAX_ITEMS: usize = 4096;

/// What an action may reach, with the facts only the caller's process knows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CiscoPlanQueryV1 {
    pub action_type: String,
    /// The selected workspace; the caller's working directory when absent.
    #[serde(default)]
    pub workspace: Option<String>,
    /// The caller's working directory (relative paths resolve against it).
    pub cwd: String,
    /// The caller's home directory, used to expand a leading `~`.
    #[serde(default)]
    pub home: Option<String>,
    #[serde(default)]
    pub approved_scan_roots: Vec<String>,
    #[serde(default)]
    pub target_paths: Vec<String>,
    pub sources: Vec<String>,
}

/// One finding reported by a third-party analyzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CiscoFindingV1 {
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub line_number: Option<i64>,
    #[serde(default)]
    pub source: String,
}

/// One ordered step of a plan: a containment signal the resident already
/// produced, or a scan the caller must run. A scan step comes back in the
/// `evidence` query with the analyzer's `status` and `findings` filled in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CiscoStepV1 {
    Signal {
        signal: Value,
    },
    Scan {
        kind: String,
        scan_root: String,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        findings: Vec<CiscoFindingV1>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CiscoEvidenceQueryV1 {
    pub steps: Vec<CiscoStepV1>,
}

/// The configured action of each risk class, resolved by the caller from its
/// config; the resident composes them. `null` means nothing is configured.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CiscoPolicyQueryV1 {
    pub signal_sources: Vec<String>,
    pub configured_actions: std::collections::BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum CiscoPreflightQueryV1 {
    Plan(CiscoPlanQueryV1),
    Evidence(CiscoEvidenceQueryV1),
    PolicyAction(CiscoPolicyQueryV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CiscoPreflightRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub query: CiscoPreflightQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CiscoPreflightResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Value,
}
