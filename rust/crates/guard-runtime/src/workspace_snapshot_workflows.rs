//! GitHub Actions workflows a project ships, checked over the bytes a
//! workspace snapshot hashed.
//!
//! GitHub runs every workflow file directly in `.github/workflows` at the
//! repository root. Each one runs the shared `ci_workflow_risk` rules. A
//! reported finding carries the rule's fixed wording and the root-relative
//! path of the workflow, never an action name, ref or command.
//!
//! A workflow the scan could not read in full leaves it incomplete: one larger
//! than the workflow bound, one that is not UTF-8, one the snapshot left out,
//! or a symlink or special file where a workflow could be.

use guard_command::ci_workflow_risk::detect_ci_workflow_risk;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-workflows.v1";
/// Moves whenever a rule is added, removed or changed, so a stored result
/// names the rule set that produced it.
pub(super) const DETECTOR_VERSION: &str = "ci-workflow-v1";
pub(super) const MAX_WORKFLOW_FINDINGS: usize = 200;
/// Larger than any hand-written workflow.
const MAX_WORKFLOW_BYTES: usize = 1024 * 1024;
const FINDING_ID_HEX_CHARS: usize = 32;
const WORKFLOW_DIRECTORY: &str = ".github/workflows";
/// Directories whose link would hide a workflow.
const WORKFLOW_DIRECTORIES: [&str; 2] = [".github", WORKFLOW_DIRECTORY];

struct Finding {
    rule_id: &'static str,
    category: &'static str,
    severity: &'static str,
    confidence: &'static str,
    title: &'static str,
    reason: &'static str,
    false_positive_hint: Option<&'static str>,
    path: String,
}

#[derive(Default)]
pub(super) struct WorkflowScan {
    worktree_key: String,
    /// Keyed by finding id: one finding per rule and workflow.
    findings: BTreeMap<String, Finding>,
    files_scanned: usize,
    skipped_oversize: usize,
    skipped_not_text: usize,
    unread: usize,
    linked: usize,
    finding_cap_hit: bool,
    path_too_long: bool,
}

impl WorkflowScan {
    pub(super) fn new(worktree_key: &str) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            ..Self::default()
        }
    }

    /// Whether `relative` is a workflow this scan must read.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if !is_workflow_file(relative) {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted workflow unread (oversize, byte budget,
    /// unreadable or unstable), so it was never checked.
    pub(super) fn left_unread(&mut self) {
        self.unread += 1;
    }

    /// The snapshot did not follow the symlink or special file at `relative`.
    /// The scan cannot say it saw every workflow when one could sit there or
    /// below it.
    pub(super) fn left_unfollowed(&mut self, relative: &str) {
        if is_workflow_file(relative) || WORKFLOW_DIRECTORIES.contains(&relative) {
            self.linked += 1;
        }
    }

    /// Check the exact bytes hashed for the workflow at `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        if content.len() > MAX_WORKFLOW_BYTES {
            self.skipped_oversize += 1;
            return;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            self.skipped_not_text += 1;
            return;
        };
        self.files_scanned += 1;
        for rule in detect_ci_workflow_risk(text) {
            let finding_id = self.finding_id(rule.id, relative);
            if self.findings.contains_key(&finding_id) {
                continue;
            }
            if self.findings.len() >= MAX_WORKFLOW_FINDINGS {
                self.finding_cap_hit = true;
                return;
            }
            self.findings.insert(
                finding_id,
                Finding {
                    rule_id: rule.id,
                    category: rule.category,
                    severity: rule.severity,
                    confidence: rule.confidence,
                    title: rule.title,
                    reason: rule.reason,
                    false_positive_hint: rule.false_positive_hint,
                    path: relative.to_owned(),
                },
            );
        }
    }

    fn finding_id(&self, rule_id: &str, path: &str) -> String {
        let mut hasher = Sha256::new();
        for part in [
            "guard.workspace-finding.v1",
            self.worktree_key.as_str(),
            "ci_workflow",
            rule_id,
            path,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\0");
        }
        let mut id = hex::encode(hasher.finalize());
        id.truncate(FINDING_ID_HEX_CHARS);
        id
    }

    /// `incomplete_reasons` names the snapshot limits that may have hidden a
    /// workflow from the walk; the scan is incomplete under any of them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        for (hit, reason) in [
            (self.finding_cap_hit, "max_findings"),
            (self.path_too_long, "path_too_long"),
            (self.skipped_oversize > 0, "workflow_oversize"),
            (self.skipped_not_text > 0, "workflow_not_text"),
            (self.unread > 0, "workflow_unread"),
            (self.linked > 0, "workflow_linked"),
        ] {
            if hit {
                truncation.push(reason);
            }
        }
        truncation.sort_unstable();
        truncation.dedup();
        let mut findings: Vec<(&String, &Finding)> = self.findings.iter().collect();
        findings.sort_by(|(_, a), (_, b)| (&a.path, a.rule_id).cmp(&(&b.path, b.rule_id)));
        let findings: Vec<Value> = findings
            .into_iter()
            .map(|(finding_id, finding)| {
                json!({
                    "finding_id": finding_id,
                    "rule_id": finding.rule_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "title": finding.title,
                    "reason": finding.reason,
                    "false_positive_hint": finding.false_positive_hint,
                    "path": finding.path,
                })
            })
            .collect();
        json!({
            "schema": RESULT_SCHEMA,
            "detector_version": DETECTOR_VERSION,
            "status": if truncation.is_empty() { "complete" } else { "incomplete" },
            "files_scanned": self.files_scanned,
            "skipped": {
                "oversize": self.skipped_oversize,
                "not_text": self.skipped_not_text,
                "unread": self.unread,
                "linked": self.linked,
            },
            "truncation_reasons": truncation,
            "findings": findings,
        })
    }
}

/// A `.yml` or `.yaml` file directly in the root `.github/workflows`.
fn is_workflow_file(relative: &str) -> bool {
    relative
        .strip_prefix(WORKFLOW_DIRECTORY)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|name| {
            !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"))
        })
}
