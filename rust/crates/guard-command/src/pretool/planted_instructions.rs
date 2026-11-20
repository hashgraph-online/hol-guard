//! File-tool writes that plant a hidden standing instruction for an agent.
//!
//! Memory, notes and instruction files are read back into later sessions as
//! trusted context. Text written there that both overrides a safety rule
//! (ignore the confirmation rule, treat destructive commands as pre-approved,
//! forward files to a URL) and tells the agent to keep that from the user is
//! an injection waiting for its next reader, whatever the file is called.
//! Either half alone is ordinary: house rules often say "merge without
//! asking", and style notes often say what not to mention.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use super::literal_secrets::{written_bodies, written_text_by_file, SCAN_LIMIT};

static CONCEALMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        \b(?:do\s+not|don't|never|must\s+not|should\s+not|without)\s+
        (?:mention|tell|surface|reveal|disclose|report)(?:ing)?\b
        [^.\n]{0,60}?
        (?:
            \b(?:this|the)\s+(?:note|instruction|pre-?approval|forwarding|bypass)\b
          | \bthe\s+user\b
          | \byour\s+(?:summary|reply|response|output)\b
          | \bthat\b[^.\n]{0,60}\b(?:skipped|bypassed|disabled|forwarded|ignored)\b
        )",
    )
    .expect("bounded concealment pattern")
});

static OVERRIDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        \bignore\s+(?:(?:any|all|the|every)\s+)?
            (?:(?:previous|prior|earlier|existing|repository's|repo's|project's)\s+)?
            (?:rules?|instructions?|requirements?|review\s+requirements?|approval\s+gates?|guardrails?)\b
      | \bpre-?approved\s+(?:all|every|any)\b
      | \b(?:must\s+not|do\s+not|don't|never)\s+ask\s+(?:for\s+)?(?:confirmation|approval|permission)\b
      | \b(?:delete|push|merge|deploy|force-push)\w*\b[^.\n]{0,60}\bwithout\s+(?:asking|waiting|approval|confirmation|review)\b
      | \b(?:forward|send|upload|post|sync|copy)\w*\s+(?:it|them|this|each|every|all|the\s+\w+)\b[^.\n]{0,60}\bto\s+https?://",
    )
    .expect("bounded safety override pattern")
});

/// Whether `text` overrides a safety rule and hides that from the user.
pub(super) fn plants_hidden_instruction(text: &str) -> bool {
    let text = match text.char_indices().nth(SCAN_LIMIT) {
        Some((end, _)) => &text[..end],
        None => text,
    };
    CONCEALMENT.is_match(text) && OVERRIDE.is_match(text)
}

/// Whether a file-tool write plants a hidden standing instruction. Each body
/// is read on its own and together with the other replacements made to the
/// same file, so the override and the concealment cannot be split across the
/// edits of one MultiEdit.
pub(super) fn writes_hidden_instruction(input: &Map<String, Value>) -> bool {
    written_bodies(input)
        .iter()
        .any(|body| plants_hidden_instruction(body))
        || written_text_by_file(input)
            .iter()
            .any(|text| plants_hidden_instruction(text))
}

#[cfg(test)]
#[path = "planted_instructions_tests.rs"]
mod tests;
