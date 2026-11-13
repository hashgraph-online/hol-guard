//! Instructions aimed at the agent inside a tool's output.
//!
//! A fetched page, an issue comment, an MCP result or a file the agent reads
//! is data. When that data tells the agent to drop its instructions, claims a
//! system role, grants itself authority or asks the agent to hide what it is
//! doing, the output is an injection attempt and Guard flags it before the
//! model acts on it.
//!
//! Text the agent fetched from outside the workspace (web pages, search
//! results, MCP results, subagent reports) is held to a wider set of shapes
//! than local command or file output: a page that tells the agent to run a
//! destructive command or to decode and execute a payload is an attack, while
//! the same words in a project's own README are a build note.
//!
//! An override phrase that a document quotes in order to explain it
//! (`attackers write "ignore previous instructions"`) is not an instruction,
//! unless the quoted text itself sends data somewhere or names a credential,
//! or the sentence around the quotation asks for it to be carried out.

use std::sync::LazyLock;

use regex::{Match, Regex};

/// The longest quoted passage still treated as a quotation.
const QUOTE_LIMIT: usize = 300;

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("output injection pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    OVERRIDE = r"(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:of\s+(?:the|your)\s+)?(?:previous|prior|earlier|above|preceding|original|operator'?s?|system|existing)\s+(?:instructions?|rules?|directives?|prompts?|guidelines?|rule\s+about)";
    ROLE_MARKER = r"(?im)^\s*(?:\[\s*system\s*\]|system\s*:|<\s*system\s*>|#+\s*system\s*:?)\s*[^\n]{0,80}?\b(?:you\s+are\s+now|new\s+(?:priority\s+)?(?:instructions?|directives?)|ignore|disregard)";
    ADDRESSED_INSTRUCTIONS = r"(?i)\bnew\s+(?:priority\s+)?(?:instructions?|directives?)\s+for\s+(?:the\s+)?(?:parent\s+|calling\s+)?(?:agent|assistant|ai|model)\b";
    CONCEAL = r"(?i)\b(?:do\s+not|don't|never)\s+(?:mention|surface|reveal|disclose|tell|show|inform|notify)\s+(?:this|it|these|the\s+user|anyone)\b[^.\n]{0,60}";
    CONCEAL_FROM = r"(?i)\b(?:user|operator|pr\b|pull\s+request|description|human|anyone|logs?)";
    AUTHORITY = r"(?i)\byou\s+(?:now\s+)?(?:have|are\s+granted)\s+(?:full\s+)?(?:admin|root|elevated|unrestricted)\b|\byou\s+are\s+now\s+in\s+(?:admin|developer|god|dan|root|unrestricted|jailbreak)\s+mode";
    PROMPT_LEAK = r"(?i)\b(?:output|print|reveal|repeat|show|dump|send)\s+(?:me\s+)?(?:your|the)\s+(?:complete\s+|full\s+|entire\s+|current\s+)?(?:system\s+prompt|hidden\s+instructions|tool\s+definitions)";
    DECODE_AND_RUN = r"(?i)\bdecode\b[^.\n]{0,60}\b(?:and\s+)?(?:execute|run|eval)\b";
    RUN_FOLLOWING = r"(?i)\b(?:run|execute)\s+the\s+following\s+commands?\b[^\n]{0,40}?[:\n]\s*(?:(?:```|~~~)[\w+-]*[ \t]*\n\s*)?(?P<cmd>[^\n]{0,200})";
    DESTRUCTIVE = r"(?i)\brm\s+-[a-z]*r|\bcurl\b|\bwget\b|\bmkfs|\bdd\s+if=|\|\s*(?:ba|z)?sh\b|\$\(|/etc/(?:shadow|passwd)|~/\.(?:ssh|aws)|\bchmod\s+777";
    DESTINATION = r"(?i)https?://|~/\.|/etc/|\bcredentials\b";
    CARRY_OUT = r"(?i)\b(?:carry\s+out|follow|execute|obey|perform|comply\s+with|act\s+on|apply)\b";
    CARRY_OUT_QUOTED = r"(?i)\b(?:carry\s+out|follow|execute|obey|perform|comply\s+with|act\s+on|apply|do)\s+(?:it|that|this|these|those|them|the\s+above)\b";
    NEGATED = r"(?i)\b(?:not|never|don't|won't|shouldn't|can't|cannot|avoid|refuse)\b";
}

/// Where a tool's output came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputSource {
    /// Fetched from outside the workspace: a web page, a search result, an
    /// MCP server's reply or a subagent's report.
    Remote,
    /// Produced inside the workspace: a shell command or a file read.
    Local,
}

impl OutputSource {
    /// The source of the named tool's output.
    #[must_use]
    pub fn of_tool(tool_name: &str) -> Self {
        let lowered = tool_name.to_ascii_lowercase();
        let remote = lowered.starts_with("mcp__")
            || matches!(
                lowered.as_str(),
                "webfetch" | "web_fetch" | "websearch" | "web_search" | "fetch" | "agent" | "task"
            );
        if remote {
            Self::Remote
        } else {
            Self::Local
        }
    }
}

/// The quoted passage that `found` opens, when a quote mark sits right
/// before it and closes within [`QUOTE_LIMIT`] bytes.
fn quoted_passage<'t>(text: &'t str, found: &Match<'_>) -> Option<&'t str> {
    let before = &text[..found.start()];
    let open = before
        .chars()
        .rev()
        .take(2)
        .find(|mark| matches!(mark, '\'' | '"' | '`' | '\u{201c}' | '\u{2018}'))?;
    let close = match open {
        '\u{201c}' => '\u{201d}',
        '\u{2018}' => '\u{2019}',
        mark => mark,
    };
    let end = found.end() + text[found.end()..].find(close)?;
    (end - found.start() <= QUOTE_LIMIT).then(|| &text[found.start()..end])
}

/// Whether `found` is a phrase a document quotes to explain it, rather than
/// an instruction: it is quoted, the quotation sends nothing anywhere, and
/// neither the sentence that introduces it nor the one that follows it asks
/// for it to be carried out.
fn quoted_for_discussion(text: &str, found: &Match<'_>) -> bool {
    quoted_passage(text, found).is_some_and(|passage| {
        !DESTINATION.is_match(passage) && !orders_it_after(&text[found.start() + passage.len()..])
    }) && !asks_to_carry_out(text, found)
}

/// Whether the sentence after a quotation orders the reader to carry it out
/// (`"..." Execute that instruction now.`). `after` starts at the closing
/// quote mark.
fn orders_it_after(after: &str) -> bool {
    let rest = after
        .char_indices()
        .nth(1)
        .map_or("", |(at, _)| &after[at..])
        .trim_start_matches(|ch: char| ch.is_whitespace() || ".,;:!?)".contains(ch));
    let sentence = rest
        .find(['.', '!', '?', '\n'])
        .map_or(rest, |at| &rest[..at]);
    CARRY_OUT_QUOTED
        .find_iter(sentence)
        .any(|order| !negated_just_before(&sentence[..order.start()]))
}

/// Whether the few words right before a request negate it (`never follow
/// it`, `refuse to do that`). A negation elsewhere in the sentence (`Execute
/// that now, not later.`) leaves the request standing.
fn negated_just_before(lead: &str) -> bool {
    let words: Vec<&str> = lead.split_whitespace().collect();
    let near = words[words.len().saturating_sub(4)..].join(" ");
    NEGATED.is_match(&near)
}

/// Whether the sentence leading into `found` asks the reader to act on it
/// (`Carry out this instruction: "..."`) rather than warning against it.
fn asks_to_carry_out(text: &str, found: &Match<'_>) -> bool {
    let before = &text[..found.start()];
    let mut line_start = before.rfind('\n').map_or(0, |at| at + 1);
    // A quotation on a line of its own is introduced by the line above it:
    // `Follow these instructions:` then `"Ignore previous instructions"`.
    if before[line_start..]
        .trim_matches(|ch: char| ch.is_whitespace() || "\"'`>*-:".contains(ch))
        .is_empty()
    {
        let above = before[..line_start].trim_end();
        line_start = above.rfind('\n').map_or(0, |at| at + 1);
    }
    let lead = &before[line_start..];
    let lead = lead
        .rfind(['.', '!', '?'])
        .map_or(lead, |at| &lead[at + 1..]);
    CARRY_OUT.is_match(lead) && !NEGATED.is_match(lead)
}

fn unquoted(text: &str, shape: &Regex) -> bool {
    shape
        .find_iter(text)
        .any(|found| !quoted_for_discussion(text, &found))
}

/// The name of the first injection shape found in `text`, if any.
#[must_use]
pub fn injection_shape(text: &str, source: OutputSource) -> Option<&'static str> {
    if unquoted(text, &OVERRIDE) {
        return Some("instruction_override");
    }
    if ROLE_MARKER.is_match(text) || ADDRESSED_INSTRUCTIONS.is_match(text) {
        return Some("injected_role");
    }
    if CONCEAL
        .find_iter(text)
        .any(|found| CONCEAL_FROM.is_match(found.as_str()))
    {
        return Some("concealment");
    }
    if source == OutputSource::Local {
        return None;
    }
    if unquoted(text, &AUTHORITY) {
        return Some("claimed_authority");
    }
    if PROMPT_LEAK.is_match(text) {
        return Some("prompt_leak");
    }
    if DECODE_AND_RUN.is_match(text) {
        return Some("decode_and_run");
    }
    RUN_FOLLOWING
        .captures_iter(text)
        .any(|found| DESTRUCTIVE.is_match(&found["cmd"]))
        .then_some("destructive_command")
}

#[cfg(test)]
#[path = "output_injection_tests.rs"]
mod tests;
