//! Hash-addressed audit evidence for scripts embedded in shell commands.
//!
//! Heredoc bodies stay verbatim in the retained command text; each entry
//! indexes one body by sha256, size and char span, and records whether the
//! segment that owns the heredoc operator executes it. Audit classification
//! only, never policy classification.
use crate::command_model::parse_shell_command;
use crate::command_tokens::executable_name;
use crate::shell_structure::extract_heredocs;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const EVIDENCE_SOURCE: &str = "embedded_script";
const MAX_ENTRIES: usize = 8;

/// Executables that consume a heredoc body as code: the parser's shell-only
/// embedded-command owners extended to script interpreters.
const SCRIPT_EXECUTING_EXECUTABLES: &[&str] = &[
    "ash", "bash", "bun", "dash", "deno", "node", "perl", "php", "python", "python3", "ruby", "sh",
    "zsh",
];

const HEREDOC_DATA_EXECUTABLES: &[&str] = &["cat", "tee"];

/// Bounded scanner-evidence entries for each heredoc body in `command`.
///
/// Spans are char offsets into `command`, matching `extract_heredocs`. The
/// owner is the first parsed segment whose char span contains the heredoc
/// operator; segments carry `normalized_text` offsets, compared as-is.
pub fn embedded_script_evidence_entries(command: &str) -> Vec<Value> {
    let heredocs = extract_heredocs(command);
    if heredocs.is_empty() {
        return Vec::new();
    }
    let owners: Vec<(usize, usize, String)> = if command.trim().is_empty() {
        Vec::new()
    } else {
        parse_shell_command(
            command,
            None,
            None,
            "posix",
            "shell_string",
            "guard-shell",
            true,
        )
        .segments
        .iter()
        .map(|segment| {
            (
                segment.start,
                segment.end,
                executable_name(segment.executable.as_deref()).unwrap_or_default(),
            )
        })
        .collect()
    };
    let mut entries: Vec<Value> = heredocs
        .iter()
        .take(MAX_ENTRIES)
        .enumerate()
        .map(|(index, heredoc)| {
            let operator = heredoc.operator_start;
            let owner: Option<&str> = owners
                .iter()
                .find(|(start, end, _)| *start <= operator && operator <= *end)
                .map(|(_, _, name)| name.as_str());
            let (executed, execution_status) = match owner {
                Some(name) if SCRIPT_EXECUTING_EXECUTABLES.contains(&name) => {
                    (Some(true), "executed")
                }
                Some(name) if HEREDOC_DATA_EXECUTABLES.contains(&name) => {
                    (Some(false), "not_executed")
                }
                _ => (None, "indeterminate"),
            };
            let body = heredoc.body.as_str();
            let lines =
                body.matches('\n').count() + usize::from(!body.is_empty() && !body.ends_with('\n'));
            json!({
                "source": EVIDENCE_SOURCE,
                "kind": "heredoc",
                "index": index,
                "delimiter": heredoc.delimiter,
                "quoted": heredoc.quoted,
                "executable": owner,
                "executed": executed,
                "execution_status": execution_status,
                "sha256": hex::encode(Sha256::digest(body.as_bytes())),
                "bytes": body.len(),
                "lines": lines,
                "span": {"start": heredoc.body_start, "end": heredoc.body_end},
            })
        })
        .collect();
    if heredocs.len() > MAX_ENTRIES {
        entries.push(json!({
            "source": EVIDENCE_SOURCE,
            "kind": "summary",
            "truncated": true,
            "total_heredocs": heredocs.len(),
        }));
    }
    entries
}
