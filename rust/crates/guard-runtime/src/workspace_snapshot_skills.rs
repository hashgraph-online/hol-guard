//! Deterministic skill-content detection over the bytes a workspace snapshot
//! hashed.
//!
//! The rules are the shared `skill_content_risk` set that also runs at hook
//! time; this module only decides which snapshot files are agent skills and
//! reduces each signal to a value that is safe to store. A reported finding
//! carries the rule id, its category, severity and confidence, the fixed rule
//! title and reason, and the root-relative path. The rule's technical detail
//! can quote skill text, so it is dropped here and never serialized.
//!
//! A skill is a `SKILL.md` under `.claude/skills`, `.agents/skills`,
//! `.codex/skills`, `.devin/skills` or `.opencode/skills` at any depth, or
//! under a top-level `skills/` directory. A skill the scan could not read in
//! full leaves it incomplete: one larger than the hook-time skill bound, one
//! that is not UTF-8 text, one the snapshot itself left out, or a symlink or
//! special file where a skill could be (the snapshot never follows links).
//! Skill roots nest at any depth, so a link to a directory the walk never
//! reaches (outside the worktree, or under a skipped directory) could hide
//! one too; a link whose target the walk reads elsewhere is harmless.

use guard_command::skill_content_risk::detect_skill_content_risk;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

use crate::runner_authority_detector::SKILL_CONTENT_MAX_BYTES;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-skills.v1";
/// Moves whenever a rule is added, removed or changed, so a stored result
/// names the rule set that produced it.
pub(super) const DETECTOR_VERSION: &str = "skill-content-v1";
pub(super) const MAX_SKILL_FINDINGS: usize = 200;
const FINDING_ID_HEX_CHARS: usize = 32;
const SKILL_FILE: &str = "SKILL.md";
/// Skill directories agents load from at any depth of a workspace.
const NESTED_SKILL_ROOTS: [&str; 5] = [
    ".claude/skills",
    ".agents/skills",
    ".codex/skills",
    ".devin/skills",
    ".opencode/skills",
];
/// Skill directory recognized only at the workspace root; a nested `skills/`
/// is too often ordinary project content.
const TOP_LEVEL_SKILL_ROOT: &str = "skills/";

struct Finding {
    finding_id: String,
    rule_id: String,
    category: &'static str,
    severity: &'static str,
    confidence: &'static str,
    title: String,
    reason: String,
    false_positive_hint: Option<String>,
    path: String,
}

#[derive(Default)]
pub(super) struct SkillScan {
    worktree_key: String,
    /// The worktree root as requested and as resolved, for link targets.
    roots: Vec<PathBuf>,
    findings: Vec<Finding>,
    files_scanned: usize,
    bytes_scanned: u64,
    skipped_oversize: usize,
    skipped_not_text: usize,
    unread: usize,
    linked: usize,
    finding_cap_hit: bool,
    path_too_long: bool,
}

impl SkillScan {
    pub(super) fn new(worktree_key: &str, roots: &[&Path]) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            roots: roots.iter().map(|root| root.to_path_buf()).collect(),
            ..Self::default()
        }
    }

    /// Whether `relative` is an agent skill this scan must read.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if !is_skill_path(relative) {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted skill unread (oversize, byte budget,
    /// unreadable or unstable), so its rules never ran.
    pub(super) fn left_unread(&mut self) {
        self.unread += 1;
    }

    /// The snapshot did not follow a special file at `relative`. When a
    /// skill could sit there, the scan cannot say it saw every skill.
    pub(super) fn left_special(&mut self, relative: &str) {
        if may_hold_skills(relative) {
            self.linked += 1;
        }
    }

    /// The snapshot did not follow the symlink at `relative` to `target`.
    /// Besides a link where a skill could sit, a link the walk cannot see
    /// through could hide a nested skill root.
    pub(super) fn left_link(&mut self, relative: &str, target: Option<&Path>) {
        if may_hold_skills(relative)
            || !target.is_some_and(|target| walked(&self.roots, relative, target))
        {
            self.linked += 1;
        }
    }

    /// Run the skill rules over the exact bytes that were hashed for `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        if content.len() > SKILL_CONTENT_MAX_BYTES {
            self.skipped_oversize += 1;
            return;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            self.skipped_not_text += 1;
            return;
        };
        self.files_scanned += 1;
        self.bytes_scanned += content.len() as u64;
        let mut signals = detect_skill_content_risk(text);
        signals.sort_by(|a, b| a.signal_id.cmp(&b.signal_id));
        signals.dedup_by(|a, b| a.signal_id == b.signal_id);
        for signal in signals {
            if self.findings.len() >= MAX_SKILL_FINDINGS {
                self.finding_cap_hit = true;
                return;
            }
            self.findings.push(Finding {
                finding_id: self.finding_id(&signal.signal_id, relative),
                rule_id: signal.signal_id,
                category: signal.category.as_str(),
                severity: signal.severity.as_str(),
                confidence: signal.confidence.as_str(),
                title: signal.title,
                reason: signal.plain_reason,
                false_positive_hint: signal.false_positive_hint,
                path: relative.to_owned(),
            });
        }
    }

    fn finding_id(&self, rule_id: &str, path: &str) -> String {
        let mut hasher = Sha256::new();
        for part in [
            "guard.workspace-finding.v1",
            self.worktree_key.as_str(),
            "skill",
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
    /// skill from the walk; the scan is incomplete under any of them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        if self.finding_cap_hit {
            truncation.push("max_findings");
        }
        if self.path_too_long {
            truncation.push("path_too_long");
        }
        if self.skipped_oversize > 0 {
            truncation.push("skill_oversize");
        }
        if self.skipped_not_text > 0 {
            truncation.push("skill_not_text");
        }
        if self.unread > 0 {
            truncation.push("skill_unread");
        }
        if self.linked > 0 {
            truncation.push("skill_linked");
        }
        truncation.sort_unstable();
        truncation.dedup();
        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by(|a, b| (&a.path, &a.rule_id).cmp(&(&b.path, &b.rule_id)));
        let findings: Vec<Value> = findings
            .into_iter()
            .map(|finding| {
                json!({
                    "finding_id": finding.finding_id,
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
            "bytes_scanned": self.bytes_scanned,
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

/// Whether the walk reads `target` (linked from `relative`) at its own
/// path: it resolves inside the worktree and outside skipped directories.
/// A link there to yet another link is judged where that link sits.
pub(super) fn walked(roots: &[PathBuf], relative: &str, target: &Path) -> bool {
    let inside = if target.is_absolute() {
        roots
            .iter()
            .find_map(|root| target.strip_prefix(root).ok())
            .map(Path::to_path_buf)
    } else {
        Path::new(relative)
            .parent()
            .map(|parent| parent.join(target))
    };
    let Some(inside) = inside else {
        return false;
    };
    let mut depth = 0usize;
    for component in inside.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::Normal(name)
                if !name
                    .to_str()
                    .is_some_and(|name| super::SKIP_DIRS.contains(&name)) =>
            {
                depth += 1
            }
            _ => return false,
        }
    }
    true
}

fn is_skill_path(relative: &str) -> bool {
    let Some((directory, basename)) = relative.rsplit_once('/') else {
        return false;
    };
    if basename != SKILL_FILE {
        return false;
    }
    let directory = format!("/{directory}/");
    relative.starts_with(TOP_LEVEL_SKILL_ROOT)
        || NESTED_SKILL_ROOTS
            .iter()
            .any(|root| directory.contains(&format!("/{root}/")))
}

/// Whether a skill could lie at or below `relative`: a skill file, an entry
/// under a skill root, a skill root itself, or the agent directory holding one
/// (a linked `.claude` hides `.claude/skills`).
fn may_hold_skills(relative: &str) -> bool {
    if is_skill_path(relative) || relative == "skills" || relative.starts_with(TOP_LEVEL_SKILL_ROOT)
    {
        return true;
    }
    let path = format!("/{relative}/");
    NESTED_SKILL_ROOTS.iter().any(|root| {
        let agent_directory = root
            .split_once('/')
            .map_or(*root, |(directory, _)| directory);
        path.contains(&format!("/{root}/")) || path.ends_with(&format!("/{agent_directory}/"))
    })
}
