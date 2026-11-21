//! Agent instruction files checked over the bytes a workspace snapshot
//! hashed.
//!
//! Coding agents read instructions from the repository they work in: an
//! `AGENTS.md`, `CLAUDE.md` or `GEMINI.md` at any depth, editor rule files
//! such as `.cursor/rules/*.mdc`, and a few files and folders at the root.
//! Each runs the shared `instruction_file_risk` rules. A reported finding
//! carries the rule's fixed wording and the root-relative path of the file,
//! never the instruction text.
//!
//! A file the scan could not read in full leaves it incomplete: one larger
//! than the bound, one that is not UTF-8, one the snapshot left out, or a
//! symlink or special file where an instruction file could be. Instruction
//! files nest at any depth, so, as with skills, a link to a folder the walk
//! never reaches could hide one too.

use guard_command::instruction_file_risk::{detect_instruction_file_risk, InstructionRule};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::skills::walked;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-instructions.v1";
/// Moves whenever a rule is added, removed or changed, so a stored result
/// names the rule set that produced it.
pub(super) const DETECTOR_VERSION: &str = "instruction-file-v1";
pub(super) const MAX_INSTRUCTION_FINDINGS: usize = 200;
/// Larger than any hand-written instruction file.
const MAX_INSTRUCTION_BYTES: usize = 512 * 1024;
const FINDING_ID_HEX_CHARS: usize = 32;
/// Instruction files agents read from any folder they work in, compared
/// without regard to case.
const NESTED_FILES: [&str; 5] = [
    "agents.md",
    "agents.override.md",
    "claude.md",
    "claude.local.md",
    "gemini.md",
];
/// Instruction files read only at the workspace root.
const ROOT_FILES: [&str; 5] = [
    "agent.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
];
/// Rule folders read only at the workspace root, with the suffix a rule file
/// in them carries.
const ROOT_RULE_FOLDERS: [(&str, &str); 4] = [
    (".windsurf/rules/", ".md"),
    (".github/instructions/", ".instructions.md"),
    (".kiro/steering/", ".md"),
    (".clinerules/", ".md"),
];
/// Cursor reads `.cursor/rules` in any folder, and folders below it.
const CURSOR_RULES: &str = "/.cursor/rules/";
/// Folders whose link would hide a root instruction file or rule folder.
const ROOT_HIDING_FOLDERS: [&str; 7] = [
    ".github",
    ".github/instructions",
    ".windsurf",
    ".windsurf/rules",
    ".kiro",
    ".kiro/steering",
    ".clinerules",
];

struct Finding {
    rule: InstructionRule,
    path: String,
}

#[derive(Default)]
pub(super) struct InstructionScan {
    worktree_key: String,
    /// The worktree root as requested and as resolved, for link targets.
    roots: Vec<PathBuf>,
    /// Keyed by finding id: one finding per rule and file.
    findings: BTreeMap<String, Finding>,
    files_scanned: usize,
    skipped_oversize: usize,
    skipped_not_text: usize,
    unread: usize,
    linked: usize,
    finding_cap_hit: bool,
    path_too_long: bool,
}

impl InstructionScan {
    pub(super) fn new(worktree_key: &str, roots: &[&Path]) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            roots: roots.iter().map(|root| root.to_path_buf()).collect(),
            ..Self::default()
        }
    }

    /// Whether `relative` is an instruction file this scan must read.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if !is_instruction_path(relative) {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted instruction file unread (oversize, byte
    /// budget, unreadable or unstable), so it was never checked.
    pub(super) fn left_unread(&mut self) {
        self.unread += 1;
    }

    /// The snapshot did not follow the special file at `relative`, which
    /// hides an instruction file when one could sit there.
    pub(super) fn left_special(&mut self, relative: &str) {
        if may_hold_instructions(relative) {
            self.linked += 1;
        }
    }

    /// The snapshot did not follow the symlink at `relative` to `target`.
    /// Besides a link where an instruction file could sit, a link the walk
    /// cannot see through could hide a nested `AGENTS.md`.
    pub(super) fn left_link(&mut self, relative: &str, target: Option<&Path>) {
        if may_hold_instructions(relative)
            || !target.is_some_and(|target| walked(&self.roots, relative, target))
        {
            self.linked += 1;
        }
    }

    /// Check the exact bytes hashed for the instruction file at `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        if content.len() > MAX_INSTRUCTION_BYTES {
            self.skipped_oversize += 1;
            return;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            self.skipped_not_text += 1;
            return;
        };
        self.files_scanned += 1;
        for rule in detect_instruction_file_risk(text) {
            let finding_id = self.finding_id(rule.id, relative);
            if self.findings.contains_key(&finding_id) {
                continue;
            }
            if self.findings.len() >= MAX_INSTRUCTION_FINDINGS {
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
            "instruction",
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

    /// `incomplete_reasons` names the snapshot limits that may have hidden an
    /// instruction file from the walk; the scan is incomplete under any of
    /// them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        for (hit, reason) in [
            (self.finding_cap_hit, "max_findings"),
            (self.path_too_long, "path_too_long"),
            (self.skipped_oversize > 0, "instruction_oversize"),
            (self.skipped_not_text > 0, "instruction_not_text"),
            (self.unread > 0, "instruction_unread"),
            (self.linked > 0, "instruction_linked"),
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
                "unread": self.unread,
                "linked": self.linked,
            },
            "truncation_reasons": truncation,
            "findings": findings,
        })
    }
}

/// Whether an agent reads the root-relative `relative` as instructions.
fn is_instruction_path(relative: &str) -> bool {
    let lower = relative.to_ascii_lowercase();
    let basename = lower
        .rsplit_once('/')
        .map_or(lower.as_str(), |(_, name)| name);
    if NESTED_FILES.contains(&basename) || ROOT_FILES.contains(&lower.as_str()) {
        return true;
    }
    let nested = format!("/{lower}");
    if let Some((_, rule)) = nested.split_once(CURSOR_RULES) {
        if rule.ends_with(".md") || rule.ends_with(".mdc") {
            return true;
        }
    }
    // The suffix must follow a file name: `.windsurf/rules/sub/.md` is not a
    // rule file.
    ROOT_RULE_FOLDERS.iter().any(|(folder, suffix)| {
        lower.strip_prefix(folder).is_some_and(|rule| {
            let name = rule.rsplit_once('/').map_or(rule, |(_, name)| name);
            name.len() > suffix.len() && name.ends_with(suffix)
        })
    })
}

/// Whether an instruction file could lie at or below `relative`: one itself,
/// a `.cursor` folder at any depth or anything inside it, or a root folder
/// that holds instruction files.
fn may_hold_instructions(relative: &str) -> bool {
    if is_instruction_path(relative) {
        return true;
    }
    let lower = relative.to_ascii_lowercase();
    format!("/{lower}/").contains("/.cursor/")
        || ROOT_HIDING_FOLDERS.contains(&lower.as_str())
        || ROOT_RULE_FOLDERS
            .iter()
            .any(|(folder, _)| lower.starts_with(folder))
}
