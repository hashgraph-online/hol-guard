//! Command redirect structures and complete executable identities
//! (`runtime/command_structure.py`, 153 lines — verbatim).

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::shell_structure::{ShellHeredoc, ShellScanState};

/// `_REDIRECT_PATTERN` (:13-16) minus the leading `(?<![<>])` lookbehind —
/// the scan already guarantees position, and we check the lookbehind char
/// directly (the pattern is matched on a sliced tail where a Rust regex cannot
/// see the preceding char).
fn redirect_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Rust `regex` has no lookahead/lookbehind. `(?<![<>])` and
        // `(?![<>&])` are enforced manually around `captures` in the scan loop.
        Regex::new(
            r#"^(?P<operator>(?:\d*)(?:<>|>\||>>?|<))\s*(?P<target>"[^"]+"|'[^']+'|[^ \t\r\n;&|<>]+)"#,
        )
        .expect("redirect pattern")
    })
}

/// `CommandRedirect` (:19-33). `start`/`end` are char offsets into the
/// normalized source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRedirect {
    pub operator: String,
    pub target: String,
    pub start: usize,
    pub end: usize,
}

impl CommandRedirect {
    pub fn to_dict(&self) -> Value {
        json!({
            "operator": self.operator,
            "target": self.target,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        })
    }
}

/// `EmbeddedCommand` (:36-51).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedCommand {
    /// "substitution" | "heredoc".
    pub kind: String,
    pub text: String,
    pub execution_context: String,
    pub start: usize,
    pub end: usize,
}

impl EmbeddedCommand {
    pub fn to_dict(&self) -> Value {
        json!({
            "kind": self.kind,
            "execution_context": self.execution_context,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        })
    }
}

/// `IdentitySegment` protocol (:54-68) — the five fields the identity digest
/// reads off a segment.
#[derive(Clone, Debug)]
pub struct IdentitySegment {
    pub tokens: Vec<String>,
    pub environment_names: Vec<String>,
    pub wrapper_chain: Vec<String>,
    pub execution_context: String,
    pub pipeline_index: usize,
}

/// `build_command_security_identity` (:71-103).
pub fn build_command_security_identity(
    normalized_text: &str,
    dialect: &str,
    transport: &str,
    wrapper_chain: &[String],
    segments: &[IdentitySegment],
    redirects: &[CommandRedirect],
    embedded_commands: &[EmbeddedCommand],
) -> String {
    let payload = json!({
        "version": 2,
        "normalized_text": normalized_text,
        "dialect": dialect,
        "transport": transport,
        "wrapper_chain": wrapper_chain,
        "segments": segments
            .iter()
            .map(|segment| json!({
                "tokens": segment.tokens,
                "environment_names": segment.environment_names,
                "wrapper_chain": segment.wrapper_chain,
                "execution_context": segment.execution_context,
                "pipeline_index": segment.pipeline_index,
            }))
            .collect::<Vec<_>>(),
        "redirects": redirects
            .iter()
            .map(|item| json!([item.operator, item.target]))
            .collect::<Vec<_>>(),
        "embedded": embedded_commands
            .iter()
            .map(|item| json!([item.kind, item.text, item.execution_context]))
            .collect::<Vec<_>>(),
    });
    let mut out = Vec::new();
    // All strings/ints/arrays — always CPython-encodable.
    let _ = guard_contracts::write_canonical_json(&payload, &mut out);
    format!("command-security-v2:{:x}", Sha256::digest(&out))
}

/// `extract_command_redirects` (:106-146). Char-offset based.
pub fn extract_command_redirects(command: &str, heredocs: &[ShellHeredoc]) -> Vec<CommandRedirect> {
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut redirects: Vec<CommandRedirect> = Vec::new();
    let heredoc_operator_starts: std::collections::HashSet<usize> =
        heredocs.iter().map(|h| h.operator_start).collect();
    let mut state = ShellScanState::new();
    let mut index = 0usize;
    while index < n {
        let next_index = state.advance(&chars, index);
        if next_index != index + 1 {
            index = next_index;
            continue;
        }
        if !state.is_top_level() {
            index += 1;
            continue;
        }
        // Emulate `pattern.match(command, index)`: lookbehind char check, then
        // anchored regex on the char-sliced tail. Match span bytes → chars.
        let lookbehind_ok = index == 0 || (chars[index - 1] != '<' && chars[index - 1] != '>');
        let tail: String = chars[index..].iter().collect();
        let caps = if lookbehind_ok {
            redirect_pattern().captures(&tail)
        } else {
            None
        };
        let caps = match caps {
            Some(c) => c,
            None => {
                index += 1;
                continue;
            }
        };
        // `(?![<>&])`: the char immediately after the matched operator must not
        // be `<`, `>`, or `&` (guards `<`/`>`/`>>` matching the head of `<<`,
        // `<&`, `>&`, `>>>`).
        let op_end_in_tail = caps.name("operator").unwrap().end();
        let op_end_char = index + tail[..op_end_in_tail].chars().count();
        if op_end_char < n && matches!(chars[op_end_char], '<' | '>' | '&') {
            index += 1;
            continue;
        }
        if heredoc_operator_starts.contains(&index) {
            index += 1;
            continue;
        }
        let whole = caps.get(0).unwrap();
        let end = index + tail[..whole.end()].chars().count();
        redirects.push(CommandRedirect {
            operator: caps["operator"].to_string(),
            target: strip_quotes(&caps["target"]),
            start: index,
            end,
        });
        index = end;
    }
    for heredoc in heredocs {
        redirects.push(CommandRedirect {
            operator: if heredoc.strip_tabs {
                "<<-".to_owned()
            } else {
                "<<".to_owned()
            },
            target: heredoc.delimiter.clone(),
            start: heredoc.operator_start,
            end: heredoc.declaration_end,
        });
    }
    redirects.sort_by_key(|item| item.start);
    redirects
}

/// `_strip_quotes` (:149-153).
fn strip_quotes(value: &str) -> String {
    let stripped = value.trim();
    let chars: Vec<char> = stripped.chars().collect();
    if chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"')
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        stripped.to_owned()
    }
}
