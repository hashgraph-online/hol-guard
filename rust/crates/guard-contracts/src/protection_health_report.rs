//! `ProtectionHealthReport` — wire contract for the resident op that says
//! whether Guard is protecting this machine, and what each harness's own
//! answer is.
//!
//! The caller sends one signal per check: a status and the stable reason code
//! that proves it. Which statuses add up to `protected`, `partial` or
//! `degraded`, which failures are a platform with no such check rather than a
//! broken one, and the words an operator reads for each state are all the
//! resident's, so a caller that can reach it never phrases its own verdict.
//!
//! Every field is always present on the wire. A request field that could be
//! omitted would digest differently on each side of the call and the reply
//! would never bind to the request that asked for it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Resident feature advertising this op.
pub const PROTECTION_HEALTH_REPORT_FEATURE: &str = "protection-health-report-v1";

/// Canonical request budget. Nine checks and a hundred harnesses of short
/// identifiers sit far inside it, so a request near the bound is malformed.
pub const PROTECTION_HEALTH_REPORT_MAX_REQUEST_BYTES: usize = 256 * 1024;

/// Request schema identifier.
pub const PROTECTION_HEALTH_REPORT_REQUEST_SCHEMA: &str =
    "guard-protection-health-report-request.v1";

/// Result schema identifier.
pub const PROTECTION_HEALTH_REPORT_RESULT_SCHEMA: &str = "guard-protection-health-report-result.v1";

/// One check's proof, or its absence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectionSignalV1 {
    /// `pass`, `unknown` or `fail`; any other word is a malformed request.
    pub status: String,
    /// The stable identifier that names why, never free-form prose.
    pub reason_code: String,
}

/// Request for one machine's protection health.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectionHealthReportRequestV1 {
    /// Must equal [`PROTECTION_HEALTH_REPORT_REQUEST_SCHEMA`].
    pub schema: String,
    /// Caller-chosen identifier the reply echoes.
    pub request_id: String,
    /// The machine-wide signals, keyed by check ID. A check the caller leaves
    /// out is unproven, which is not the same as passing.
    pub signals: BTreeMap<String, ProtectionSignalV1>,
    /// Each harness's own hook signal, keyed by harness. The rest of a
    /// harness's checks are the machine-wide ones.
    pub harness_signals: BTreeMap<String, ProtectionSignalV1>,
}

/// Reply carrying the evaluated report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtectionHealthReportResultV1 {
    /// Always [`PROTECTION_HEALTH_REPORT_RESULT_SCHEMA`].
    pub schema: String,
    /// Echo of the request's identifier.
    pub request_id: String,
    /// Digest of the canonical request this reply answers.
    pub request_sha256: String,
    /// `ok` for a reply the caller may read.
    pub status: String,
    /// `ok` for a reply the caller may read.
    pub code: String,
    /// The report, under `schema_version`, `state`, `label`, `detail`,
    /// `evidence_gap`, `checks`, `reason_codes` and `apps`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
