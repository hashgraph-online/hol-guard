//! The plan a verified workspace read carries out.
//!
//! A verified workspace read is performed by Guard itself, not by the agent, so
//! something has to decide which read the argv asks for and how much of the
//! file it may show. `guard_command::verified_read_plan` answers with this
//! plan, and the `VerifiedReadExecute` op carries it out.

use serde::{Deserialize, Serialize};

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
