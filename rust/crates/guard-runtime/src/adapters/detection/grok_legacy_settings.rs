//! Runner-authority kind `grok_legacy_settings`: removes Guard's managed block
//! from Grok's legacy `managed_config.toml` and restores the `compat.<vendor>`
//! hooks values Guard replaced, as recorded in its install state. The edits
//! replay the regular expressions and `str.splitlines` walk of the original
//! Python byte for byte (see
//! `testdata/grok/record_grok_legacy_settings_vectors.py`).

use regex::Regex;
use serde_json::{json, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const BEGIN: &str = "# BEGIN HOL GUARD MANAGED GROK";
const END: &str = "# END HOL GUARD MANAGED GROK";
const MARKER: &str = "HOL GUARD MANAGED GROK";
/// Python's `\s` also matches the ASCII separators U+001C to U+001F.
const SPACE: &str = r"[\s\x1c-\x1f]";
/// The line boundaries of Python's `str.splitlines` besides `\r` and `\r\n`.
const LINE_BREAKS: [char; 9] = [
    '\n', '\u{0b}', '\u{0c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}', '\u{2029}',
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    if map.len() != 2 {
        return Err(ERR_INVALID);
    }
    let text = map.get("text").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let pairs = map
        .get("prior_compat_hooks")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let mut prior: Vec<(&str, &str)> = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Some([vendor, previous]) = pair.as_array().map(Vec::as_slice) else {
            return Err(ERR_INVALID);
        };
        let vendor = vendor.as_str().ok_or(ERR_INVALID)?;
        // A recorded value that is not text leaves that vendor's table alone.
        if let Some(previous) = previous.as_str() {
            prior.push((vendor, previous));
        }
    }
    Ok(json!({ "text": legacy_text(text, &prior)? }))
}

fn legacy_text(text: &str, prior: &[(&str, &str)]) -> Result<String, &'static str> {
    if !text.contains(BEGIN) {
        return Ok(text.to_string());
    }
    let cleaned = remove_managed_block(text)?;
    Ok(restore_compat_hooks(cleaned, prior))
}

fn compile(pattern: &str) -> Result<Regex, &'static str> {
    Regex::new(pattern).map_err(|_| ERR_INVALID)
}

fn remove_managed_block(text: &str) -> Result<String, &'static str> {
    let block = compile(&format!(
        r"(?ms)^{SPACE}*{}.*?{}{SPACE}*\n?",
        regex::escape(BEGIN),
        regex::escape(END)
    ))?;
    let marker = compile(&format!(r"(?m)^{SPACE}*#.*{}.*$\n?", regex::escape(MARKER)))?;
    let cleaned = block.replace_all(text, "");
    Ok(marker.replace_all(&cleaned, "").into_owned())
}

fn restore_compat_hooks(text: String, prior: &[(&str, &str)]) -> String {
    let mut updated = text;
    for (vendor, previous) in prior {
        let Some((start, end)) = compat_table_span(&updated, vendor) else {
            continue;
        };
        let block = &updated[start..end];
        let assignment = hooks_assignment(block);
        let restored = match assignment {
            Some((line_start, line_end, _)) if previous.is_empty() => {
                format!("{}{}", &block[..line_start], &block[line_end..])
            }
            None if previous.is_empty() => block.to_string(),
            Some((line_start, line_end, newline)) => format!(
                "{}hooks = {previous}{newline}{}",
                &block[..line_start],
                &block[line_end..]
            ),
            None => {
                let header = format!("[compat.{vendor}]");
                block.replacen(&header, &format!("{header}\nhooks = {previous}"), 1)
            }
        };
        updated = format!("{}{restored}{}", &updated[..start], &updated[end..]);
    }
    updated
}

/// The `[compat.<vendor>]` table: its header line through the next table header.
fn compat_table_span(text: &str, vendor: &str) -> Option<(usize, usize)> {
    let header = compile(&format!(
        r"(?m)^[ \t]*\[compat\.{}\][ \t]*(?:#.*)?$",
        regex::escape(vendor)
    ))
    .ok()?;
    let next = compile(r"(?m)^[ \t]*\[").ok()?;
    let found = header.find(text)?;
    let rest = &text[found.end()..];
    let tail = next.find(rest).map_or(rest.len(), |table| table.start());
    Some((found.start(), found.end() + tail))
}

/// The first `hooks = ...` line of a table and the line ending it keeps.
fn hooks_assignment(block: &str) -> Option<(usize, usize, &str)> {
    let mut offset = 0;
    for line in python_lines(block) {
        let body = line.trim_end_matches(['\r', '\n']);
        let newline = &line[body.len()..];
        let stripped = body.trim_start_matches([' ', '\t']);
        if let Some(remainder) = stripped.strip_prefix("hooks") {
            if remainder.trim_start_matches([' ', '\t']).starts_with('=') {
                return Some((offset, offset + line.len(), newline));
            }
        }
        offset += line.len();
    }
    None
}

/// Python's `str.splitlines(keepends=True)`.
fn python_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        let mut end = index + character.len_utf8();
        if character == '\r' {
            if chars.peek().is_some_and(|(_, next)| *next == '\n') {
                chars.next();
                end += 1;
            }
        } else if !LINE_BREAKS.contains(&character) {
            continue;
        }
        lines.push(&text[start..end]);
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}
