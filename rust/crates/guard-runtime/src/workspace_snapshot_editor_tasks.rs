//! Editor tasks and dev container commands a project sets to run on their
//! own, checked over the bytes a workspace snapshot hashed.
//!
//! VS Code reads tasks from `.vscode/tasks.json` and from a `.code-workspace`
//! file a person opens; dev containers read `.devcontainer.json`,
//! `.devcontainer/devcontainer.json` or one folder below `.devcontainer`.
//! Each runs the shared `editor_task_risk` rules. A reported finding carries
//! the rule's fixed wording and the root-relative path of the file, never a
//! task name or command.
//!
//! A file the scan could not read in full leaves it incomplete: one larger
//! than the bound, one that is not UTF-8 or does not parse, one the snapshot
//! left out, or a symlink or special file where such a file could be.

use guard_command::editor_task_risk::{detect_editor_task_risk, EditorConfig, EditorTaskRule};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-editor-tasks.v1";
/// Moves whenever a rule is added, removed or changed, so a stored result
/// names the rule set that produced it.
pub(super) const DETECTOR_VERSION: &str = "editor-task-v1";
pub(super) const MAX_EDITOR_TASK_FINDINGS: usize = 200;
/// Larger than any hand-written editor or dev container configuration.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const FINDING_ID_HEX_CHARS: usize = 32;
const TASKS_FILE: &str = ".vscode/tasks.json";
const DEVCONTAINER_DIRECTORY: &str = ".devcontainer";
const DEVCONTAINER_FILE: &str = "devcontainer.json";

struct Finding {
    rule: EditorTaskRule,
    path: String,
}

#[derive(Default)]
pub(super) struct EditorTaskScan {
    worktree_key: String,
    /// Keyed by finding id: one finding per rule and file.
    findings: BTreeMap<String, Finding>,
    files_scanned: usize,
    skipped_oversize: usize,
    skipped_not_text: usize,
    unparsed: usize,
    unread: usize,
    linked: usize,
    finding_cap_hit: bool,
    path_too_long: bool,
}

impl EditorTaskScan {
    pub(super) fn new(worktree_key: &str) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            ..Self::default()
        }
    }

    /// Whether `relative` is a configuration this scan must read.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if config_kind(relative).is_none() {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted configuration unread (oversize, byte
    /// budget, unreadable or unstable), so it was never checked.
    pub(super) fn left_unread(&mut self) {
        self.unread += 1;
    }

    /// The snapshot did not follow the special file at `relative`. Only one
    /// where a configuration belongs hides it; a pipe or socket is never a
    /// folder.
    pub(super) fn left_special(&mut self, relative: &str) {
        if config_kind(relative).is_some() {
            self.linked += 1;
        }
    }

    /// The snapshot did not follow the symlink at `relative`. The scan cannot
    /// say it saw every configuration when one could sit there or, for a link
    /// to a folder, below it; an unfollowed link could be either.
    pub(super) fn left_link(&mut self, relative: &str) {
        if config_kind(relative).is_some() || hides_config(relative) {
            self.linked += 1;
        }
    }

    /// Check the exact bytes hashed for the configuration at `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        let Some(kind) = config_kind(relative) else {
            return;
        };
        if content.len() > MAX_CONFIG_BYTES {
            self.skipped_oversize += 1;
            return;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            self.skipped_not_text += 1;
            return;
        };
        self.files_scanned += 1;
        let check = detect_editor_task_risk(kind, text);
        if !check.parsed {
            self.unparsed += 1;
        }
        for rule in check.rules {
            let finding_id = self.finding_id(rule.id, relative);
            if self.findings.contains_key(&finding_id) {
                continue;
            }
            if self.findings.len() >= MAX_EDITOR_TASK_FINDINGS {
                self.finding_cap_hit = true;
                return;
            }
            self.findings.insert(
                finding_id,
                Finding {
                    rule,
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
            "editor_task",
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
    /// configuration from the walk; the scan is incomplete under any of them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        for (hit, reason) in [
            (self.finding_cap_hit, "max_findings"),
            (self.path_too_long, "path_too_long"),
            (self.skipped_oversize > 0, "editor_task_oversize"),
            (self.skipped_not_text > 0, "editor_task_not_text"),
            (self.unparsed > 0, "editor_task_unparsed"),
            (self.unread > 0, "editor_task_unread"),
            (self.linked > 0, "editor_task_linked"),
        ] {
            if hit {
                truncation.push(reason);
            }
        }
        truncation.sort_unstable();
        truncation.dedup();
        let mut findings: Vec<(&String, &Finding)> = self.findings.iter().collect();
        findings.sort_by(|(_, a), (_, b)| (&a.path, a.rule.id).cmp(&(&b.path, b.rule.id)));
        let findings: Vec<Value> = findings
            .into_iter()
            .map(|(finding_id, finding)| {
                json!({
                    "finding_id": finding_id,
                    "rule_id": finding.rule.id,
                    "category": finding.rule.category,
                    "severity": finding.rule.severity,
                    "confidence": finding.rule.confidence,
                    "title": finding.rule.title,
                    "reason": finding.rule.reason,
                    "false_positive_hint": finding.rule.false_positive_hint,
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
                "unparsed": self.unparsed,
                "unread": self.unread,
                "linked": self.linked,
            },
            "truncation_reasons": truncation,
            "findings": findings,
        })
    }
}

/// The kind of configuration at the root-relative `relative`, if any.
fn config_kind(relative: &str) -> Option<EditorConfig> {
    if relative == TASKS_FILE || (!relative.contains('/') && relative.ends_with(".code-workspace"))
    {
        return Some(EditorConfig::Tasks);
    }
    if relative == ".devcontainer.json" {
        return Some(EditorConfig::DevContainer);
    }
    let rest = relative
        .strip_prefix(DEVCONTAINER_DIRECTORY)?
        .strip_prefix('/')?;
    let is_devcontainer = match rest.split_once('/') {
        None => rest == DEVCONTAINER_FILE,
        Some((folder, name)) => !folder.is_empty() && name == DEVCONTAINER_FILE,
    };
    is_devcontainer.then_some(EditorConfig::DevContainer)
}

/// A directory whose link would hide a configuration: `.vscode`,
/// `.devcontainer` or a folder directly inside it.
fn hides_config(relative: &str) -> bool {
    relative == ".vscode"
        || relative == DEVCONTAINER_DIRECTORY
        || relative
            .strip_prefix(DEVCONTAINER_DIRECTORY)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|folder| !folder.is_empty() && !folder.contains('/'))
}
