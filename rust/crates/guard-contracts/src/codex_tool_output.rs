//! The caller facts the resident's inspection host reads.
//!
//! `CodexToolOutputFactsV1` carries the observed caller state (process working
//! directory, home, account home, groups, a bounded environment snapshot and
//! the `git` executable) that every resident command review answers git and
//! environment questions from.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Observed caller facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexToolOutputFactsV1 {
    /// `os.getcwd()` of the caller.
    pub process_cwd: String,
    /// `Path.home()` of the caller.
    pub home: String,
    /// The passwd-database home of the current account, when resolvable.
    pub account_home: Option<String>,
    /// Observed process group ids (primary and supplementary).
    pub groups: Vec<u32>,
    /// Bounded snapshot of the process environment the review reads.
    pub environment: BTreeMap<String, String>,
    /// `shutil.which("git")` of the caller.
    pub git_executable: Option<String>,
}
