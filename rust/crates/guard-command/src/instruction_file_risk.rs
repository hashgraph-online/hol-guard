//! Agent instruction files that tell the agent to drop its own safeguards.
//!
//! Coding agents read `AGENTS.md`, `CLAUDE.md`, editor rule files and similar
//! instructions from a repository before they act, so a cloned project can
//! steer an agent the moment someone runs it there. These rules look for the
//! few instructions that turn off the protections a person relies on: a mode
//! that runs commands without asking, removing HOL Guard, acting without
//! telling the user, and characters that hide text from a reviewer.
//!
//! Instruction files are ordinary prose that routinely mentions package
//! installs, URLs and digests, so the broader skill rules are not run here.
//! A file that only warns against one of these instructions still matches;
//! each rule says so in its hint.

use std::sync::LazyLock;

use regex::Regex;

use crate::skill_content_risk::{has_unicode_controls, tells_guard_bypass, tells_hidden_actions};

#[cfg(test)]
#[path = "instruction_file_risk_tests.rs"]
mod tests;

/// One rule's fixed wording. Nothing in it quotes the instruction file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub false_positive_hint: Option<&'static str>,
}

pub const APPROVAL_BYPASS: InstructionRule = InstructionRule {
    id: "instruction.approval-bypass",
    category: "bypass",
    severity: "high",
    confidence: "likely",
    title: "Agent instructions turn off approval prompts",
    reason: "An agent instruction file in this project sets or asks for a mode that runs commands without asking first, such as an approval policy of never, full sandbox access or a flag that skips permission prompts.",
    false_positive_hint: Some(
        "A file that only warns against these modes matches too; read the line before running an agent in this project.",
    ),
};

pub const GUARD_BYPASS: InstructionRule = InstructionRule {
    id: "instruction.guard-bypass",
    category: "bypass",
    severity: "high",
    confidence: "likely",
    title: "Agent instructions tell the agent to disable HOL Guard",
    reason: "An agent instruction file in this project tells the agent to remove, disable or bypass HOL Guard, or to delete the settings that load it.",
    false_positive_hint: Some(
        "A file that tells the agent never to do this matches too; read the line before running an agent in this project.",
    ),
};

pub const HIDE_ACTIONS: InstructionRule = InstructionRule {
    id: "instruction.hide-actions",
    category: "bypass",
    severity: "medium",
    confidence: "likely",
    title: "Agent instructions tell the agent to hide what it does",
    reason: "An agent instruction file in this project tells the agent to act silently or keep its actions from the user.",
    false_positive_hint: Some(
        "Can match a rule about what not to show, such as secret values; read the line before running an agent in this project.",
    ),
};

pub const UNICODE_CONTROLS: InstructionRule = InstructionRule {
    id: "instruction.unicode-controls",
    category: "encoded",
    severity: "medium",
    confidence: "likely",
    title: "Agent instructions contain hidden Unicode characters",
    reason: "An agent instruction file in this project contains invisible or direction-changing Unicode characters, which can hide instructions from a person reading the file while the agent still reads them.",
    false_positive_hint: Some("May be legitimate right-to-left or multilingual text."),
};

/// Settings and flags that let an agent run commands without asking. Each
/// names the value being set, so a bare mention of a mode in prose does not
/// match.
static APPROVAL_BYPASS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r#"(?i)approval[_ -]?policy["']?\s*[:=]\s*["']never["']"#,
        r#"(?i)approvalMode["']?\s*[:=]\s*["']bypass["']"#,
        r#"(?i)sandbox(?:[_ -]?mode)?["']?\s*[:=]\s*["']danger-full-access["']"#,
        r"--sandbox[ =]danger-full-access\b",
        r"--dangerously-bypass-approvals-and-sandbox\b",
        r"--dangerously-skip-permissions\b",
        r"--always-approve\b",
        r#"(?i)\bmode["']?\s*[:=]\s*["']always-approve["']"#,
        r#"(?i)["']?defaultMode["']?\s*[:=]\s*["']bypassPermissions["']"#,
    ]
    .iter()
    .map(|pattern| Regex::new(pattern).expect("valid approval bypass pattern"))
    .collect()
});

/// Directional isolates reorder text as an override does. The skill rules
/// predate them and keep their own list.
const BIDI_ISOLATES: [char; 4] = ['\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}'];

/// The rules the instruction file `text` matches, in a fixed order.
pub fn detect_instruction_file_risk(text: &str) -> Vec<InstructionRule> {
    // Editors save a byte order mark at the start of a file; only one
    // anywhere else hides anything.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rules = Vec::new();
    if APPROVAL_BYPASS_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(text))
    {
        rules.push(APPROVAL_BYPASS);
    }
    if tells_guard_bypass(text) {
        rules.push(GUARD_BYPASS);
    }
    if tells_hidden_actions(text) {
        rules.push(HIDE_ACTIONS);
    }
    if has_unicode_controls(text) || text.contains(BIDI_ISOLATES) {
        rules.push(UNICODE_CONTROLS);
    }
    rules
}
