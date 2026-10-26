//! Request/result contract for the `VerifiedReadPlan` resident op.
//!
//! A verified workspace read is performed by Guard itself, not by the agent, so
//! something has to decide which read the argv asks for and how much of the
//! file it may show. That is command parsing and bounding, and the resident
//! owns it: the executor sends the argv and receives a plan it can carry out,
//! or an error that ends the verified read.

use serde::{Deserialize, Serialize};

pub const VERIFIED_READ_PLAN_FEATURE: &str = "verified-read-plan-v1";
pub const VERIFIED_READ_PLAN_REQUEST_SCHEMA: &str = "guard-verified-read-plan-request.v1";
pub const VERIFIED_READ_PLAN_RESULT_SCHEMA: &str = "guard-verified-read-plan-result.v1";
/// Largest request the op accepts; longer input fails closed. The cohort takes
/// at most three short arguments, so this is generous by a wide margin.
pub const VERIFIED_READ_PLAN_MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Which part of the target the executor may show.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "select", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedReadSelectionV1 {
    /// The working directory itself; there is no file to open.
    WorkingDirectory {},
    /// The first `count` lines.
    LeadingLines { count: u32 },
    /// The last `count` lines.
    TrailingLines { count: u32 },
    /// Lines `start` through `end`, both inclusive and one-based.
    LineRange { start: u32, end: u32 },
}

/// One bounded read the executor may perform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadPlanV1 {
    /// Names the operation this read belongs to, and the one the decision op
    /// is later asked about.
    pub operation_id: String,
    /// The argument naming what to read, already held to a static relative
    /// path. Absent when the plan reads no file.
    pub target: Option<String>,
    pub selection: VerifiedReadSelectionV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadPlanRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The command as the executor received it, executable first.
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadPlanResultV1 {
    pub schema: String,
    pub request_id: String,
    /// Hex SHA-256 of the canonical request serialization.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    pub code: String,
    /// Which grammar rule refused the argv, when one did. The executor only
    /// ends the read, so this is for the diagnostics record, not for control
    /// flow.
    pub detail: Option<String>,
    /// Present only when `ok`.
    pub plan: Option<VerifiedReadPlanV1>,
}
