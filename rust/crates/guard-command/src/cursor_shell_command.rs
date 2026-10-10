//! Cursor shell command normalization: unwrap `lean-ctx -c <command>` rewrites
//! so approval memory and observer proofs key on the command the user ran.
//!
//! Mirrors the retired `normalize_cursor_shell_command` including its quirk of
//! locating the marker in the lower-cased text and then indexing the stripped
//! text with that position.

use crate::codex_output_py::{py_lstrip, py_strip, shlex_split};

const MAX_NORMALIZE_CHARS: usize = 8192;
const LEAN_CTX_MARKER: &str = "lean-ctx";

/// Outcome of normalization.
#[derive(Debug, PartialEq, Eq)]
pub enum CursorShellNormalization {
    Command(String),
    /// The retired implementation raised (`IndexError`) for this input.
    Unnormalizable,
}

/// `_split_posix_single_quoted_argument`.
fn split_single_quoted(text: &str) -> Option<(String, String)> {
    let chars: Vec<char> = text.chars().collect();
    if chars.first() != Some(&'\'') {
        return None;
    }
    let mut parts = String::new();
    let mut index = 1;
    while index < chars.len() {
        if chars[index] != '\'' {
            parts.push(chars[index]);
            index += 1;
            continue;
        }
        if index + 3 < chars.len() && chars[index..index + 4] == ['\'', '\\', '\'', '\''] {
            parts.push('\'');
            index += 4;
            continue;
        }
        let rest: String = chars[index + 1..].iter().collect();
        return Some((parts, py_lstrip(&rest).to_owned()));
    }
    None
}

/// `_split_first_shell_argument`.
fn split_first_argument(text: &str) -> Option<(String, String)> {
    let text = py_lstrip(text);
    if text.is_empty() {
        return None;
    }
    if text.starts_with('\'') {
        return split_single_quoted(text);
    }
    let tokens = shlex_split(text)?;
    let first = tokens.first()?.clone();
    match text.find(first.as_str()) {
        None => Some((first, String::new())),
        Some(position) => Some((
            first.clone(),
            py_lstrip(&text[position + first.len()..]).to_owned(),
        )),
    }
}

fn join_inner(inner: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        inner.to_owned()
    } else {
        format!("{inner} {suffix}")
    }
}

fn char_slice(chars: &[char], from: usize) -> String {
    chars.get(from..).unwrap_or_default().iter().collect()
}

/// `normalize_cursor_shell_command`.
#[must_use]
pub fn normalize_cursor_shell_command(command: &str) -> CursorShellNormalization {
    let stripped = py_strip(command);
    let stripped_chars: Vec<char> = stripped.chars().collect();
    if stripped_chars.is_empty() || stripped_chars.len() > MAX_NORMALIZE_CHARS {
        return CursorShellNormalization::Command(stripped.to_owned());
    }
    let lowered: Vec<char> = stripped.to_lowercase().chars().collect();
    let needle: Vec<char> = LEAN_CTX_MARKER.chars().collect();
    let mut start = 0;
    while let Some(offset) = lowered
        .get(start..)
        .and_then(|window| window.windows(needle.len()).position(|part| part == needle))
    {
        let index = start + offset;
        if index != 0 {
            // The retired code indexed the stripped text with this position.
            let Some(previous) = stripped_chars.get(index - 1) else {
                return CursorShellNormalization::Unnormalizable;
            };
            if *previous != '/' {
                start = index + 1;
                continue;
            }
        }
        let tail = char_slice(&stripped_chars, index + needle.len());
        let tail = py_lstrip(&tail);
        if let Some(after_flag) = tail.strip_prefix("-c") {
            let rest = py_lstrip(after_flag);
            let tokens = shlex_split(rest);
            if let Some(tokens) = tokens.filter(|tokens| !tokens.is_empty()) {
                return CursorShellNormalization::Command(tokens.join(" "));
            }
            return CursorShellNormalization::Command(match split_first_argument(rest) {
                Some((inner, suffix)) => join_inner(&inner, &suffix),
                None => stripped.to_owned(),
            });
        }
        start = index + 1;
    }
    CursorShellNormalization::Command(stripped.to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use super::{normalize_cursor_shell_command, CursorShellNormalization};

    fn as_command(value: CursorShellNormalization) -> String {
        match value {
            CursorShellNormalization::Command(command) => command,
            CursorShellNormalization::Unnormalizable => panic!("python helper returns a string"),
        }
    }

    #[test]
    fn normalisation_matches_the_live_python_helper() {
        let commands = vec![
            "git status".to_owned(),
            "  git status  ".to_owned(),
            "/usr/bin/lean-ctx -c echo hi".to_owned(),
            "lean-ctx -c 'lean-ctx -c git status'".to_owned(),
            String::new(),
            "a".repeat(8193),
        ];
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let script = r#"
import json, sys
from codex_plugin_scanner.guard.adapters.cursor_native_approval import (
    normalize_cursor_shell_command,
)
commands = json.load(sys.stdin)
json.dump(
    [
        [
            normalize_cursor_shell_command(command),
            normalize_cursor_shell_command(normalize_cursor_shell_command(command)),
        ]
        for command in commands
    ],
    sys.stdout,
)
"#;
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(script)
            .current_dir(&root)
            .env("PYTHONPATH", root.join("src"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("python3");
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(
                serde_json::to_string(&commands)
                    .expect("commands")
                    .as_bytes(),
            )
            .expect("write commands");
        drop(stdin);
        let output = child.wait_with_output().expect("wait");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "python helper failed: {stderr}");
        let parsed: Vec<(String, String)> =
            serde_json::from_slice(&output.stdout).expect("python json");
        assert_eq!(parsed.len(), commands.len());
        for (command, (python_once, python_twice)) in commands.iter().zip(parsed) {
            let once = as_command(normalize_cursor_shell_command(command));
            let twice = as_command(normalize_cursor_shell_command(&once));
            assert_eq!(once, python_once, "once {command:?}");
            assert_eq!(twice, python_twice, "twice {command:?}");
        }
    }
}
