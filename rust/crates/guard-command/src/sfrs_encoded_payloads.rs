//! Encoded payload decoding and execution detection (`encoded_payloads.py`,
//! the leaf helpers and the read-only pipeline checks).
//!
//! `_looks_destructive_shell_command` itself depends on the node, TypeScript
//! and destructive-command services; callers here take it as a
//! [`DestructiveCheck`] so the recursion points stay exactly where the Python
//! has them.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::codex_output_py::py_strip;
use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_interpreter_scripts::{
    is_python_interpreter_command, script_interpreter_texts, script_is_read_only_observer,
};
use crate::sfrs_request_data::{
    BASE64_LITERAL_PATTERN, HEX_LITERAL_PATTERN, MAX_DECODED_PAYLOAD_BYTES,
};
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use crate::sfrs_substitution::{
    iter_shell_pipelines, read_backtick_command_substitution, read_command_substitution,
    shell_command_substitution_payloads,
};

/// `_looks_destructive_shell_command(text, cwd=..., home_dir=...)` with its
/// default `depth`, supplied by the caller.
pub(crate) type DestructiveCheck<'a> = &'a dyn Fn(&str, Option<&Path>, Option<&Path>) -> bool;

static SHELL_C_FLAG: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"\b(?:ash|bash|dash|sh|zsh)\b[^\n;|&]*-[A-Za-z]*c[A-Za-z]*"#));
static EVAL_SUBSTITUTION: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"\beval\b[^\n;|&]*\$\("#));
static DECODE_PRIMITIVES: LazyLock<Vec<FancyRegex>> = LazyLock::new(|| {
    vec![
        compile_fancy(r#"\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))"#),
        compile_fancy(r#"\bxxd\s+(?:-r\s+-p|-rp)\b"#),
        compile_fancy(r#"\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b"#),
        compile_fancy(r#"\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b"#),
    ]
});

/// A regex failure (backtracking limit) is read as a match: the detections
/// below are blockers, so the safe direction is "found".
pub(crate) fn pattern_found(pattern: &FancyRegex, text: &str) -> bool {
    pattern.is_match(text).unwrap_or(true)
}

/// `_contains_command_substitution_decode_exec`.
pub(crate) fn contains_command_substitution_decode_exec(command_text: &str) -> bool {
    let payloads = shell_command_substitution_payloads(command_text);
    if payloads.is_empty() || !payloads.iter().any(|p| contains_decode_primitive(p)) {
        return false;
    }
    let lowered = command_text.to_lowercase();
    pattern_found(&SHELL_C_FLAG, &lowered) || pattern_found(&EVAL_SUBSTITUTION, &lowered)
}

/// `_contains_decode_primitive`.
pub(crate) fn contains_decode_primitive(command_text: &str) -> bool {
    let lowered = command_text.to_lowercase();
    DECODE_PRIMITIVES
        .iter()
        .any(|pattern| pattern_found(pattern, &lowered))
}

/// `_shell_text_without_quoted_literals`.
pub(crate) fn shell_text_without_quoted_literals(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    let mut single_quoted = false;
    let mut double_quoted = false;
    while index < chars.len() {
        let c = chars[index];
        if single_quoted {
            if c == '\'' {
                single_quoted = false;
            }
            out.push(' ');
            index += 1;
            continue;
        }
        if double_quoted {
            if c == '\\' {
                out.push(' ');
                if index + 1 < chars.len() {
                    out.push(' ');
                    index += 2;
                } else {
                    index += 1;
                }
                continue;
            }
            if c == '"' {
                double_quoted = false;
                out.push(' ');
                index += 1;
                continue;
            }
            if c == '$' && chars.get(index + 1) == Some(&'(') {
                let (payload, next) = read_command_substitution(&chars, index + 2);
                out.push_str(&format!("$({payload})"));
                index = next;
                continue;
            }
            if c == '`' {
                let (payload, next) = read_backtick_command_substitution(&chars, index + 1);
                out.push_str(&format!("`{payload}`"));
                index = next;
                continue;
            }
            out.push(' ');
            index += 1;
            continue;
        }
        if c == '\'' {
            single_quoted = true;
            out.push(' ');
        } else if c == '"' {
            double_quoted = true;
            out.push(' ');
        } else {
            out.push(c);
        }
        index += 1;
    }
    out
}

/// `base64.b64decode(literal, validate=True)`; `None` is `binascii.Error`.
fn b64decode_strict(literal: &str) -> Option<Vec<u8>> {
    let data = literal.trim_end_matches('=');
    let padding = literal.len() - data.len();
    if padding > 2 {
        return None;
    }
    let mut values: Vec<u8> = Vec::with_capacity(data.len());
    for byte in data.bytes() {
        values.push(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        });
    }
    if !matches!((values.len() % 4, padding), (0, 0) | (2, 2) | (3, 1)) {
        return None;
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let mut acc: u32 = 0;
        for value in chunk {
            acc = (acc << 6) | u32::from(*value);
        }
        acc <<= 6 * (4 - chunk.len());
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

/// `_decode_base64_literal`.
pub(crate) fn decode_base64_literal(literal: &str) -> Option<String> {
    decoded_bytes_to_text(&b64decode_strict(literal)?)
}

/// `_decode_hex_literal`.
pub(crate) fn decode_hex_literal(literal: &str) -> Option<String> {
    if literal.len() % 2 != 0 || !literal.is_ascii() {
        return None;
    }
    let bytes = literal.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    decoded_bytes_to_text(&out)
}

/// `_decoded_bytes_to_text`: UTF-8 first, then UTF-16-LE.
pub(crate) fn decoded_bytes_to_text(decoded: &[u8]) -> Option<String> {
    if decoded.is_empty() || decoded.len() > MAX_DECODED_PAYLOAD_BYTES {
        return None;
    }
    if let Ok(text) = std::str::from_utf8(decoded) {
        if text_is_probably_source(text) {
            return Some(text.to_owned());
        }
    }
    if decoded.len() % 2 == 0 {
        let units: Vec<u16> = decoded
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if let Ok(text) = String::from_utf16(&units) {
            if text_is_probably_source(&text) {
                return Some(text);
            }
        }
    }
    None
}

/// The general categories `str.isprintable` rejects (`Cs` cannot occur in a
/// `char`). Tables come from the regex crate's Unicode data.
static NOT_PRINTABLE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]$").expect("category class")
});

/// `str.isprintable` for one code point: everything outside `C*` and `Z*`,
/// plus the ASCII space.
pub(crate) fn py_isprintable(c: char) -> bool {
    let mut buffer = [0u8; 4];
    c == ' ' || !NOT_PRINTABLE.is_match(c.encode_utf8(&mut buffer))
}

/// `_text_is_probably_source`.
pub(crate) fn text_is_probably_source(text: &str) -> bool {
    if py_strip(text).is_empty() {
        return false;
    }
    let total = text.chars().count();
    let printable = text
        .chars()
        .filter(|c| py_isprintable(*c) || matches!(c, '\n' | '\r' | '\t'))
        .count();
    printable as f64 / total as f64 >= 0.85
}

/// `_decoded_shell_payloads`.
pub(crate) fn decoded_shell_payloads(command_text: &str) -> Vec<String> {
    let lowered = command_text.to_lowercase();
    let mut payloads: Vec<String> = Vec::new();
    if [
        "base64",
        "b64decode",
        "frombase64string",
        "-encodedcommand",
        " -enc ",
        "openssl",
        "gpg",
    ]
    .iter()
    .any(|token| lowered.contains(token))
    {
        for found in BASE64_LITERAL_PATTERN.find_iter(command_text).flatten() {
            if let Some(decoded) = decode_base64_literal(found.as_str()) {
                payloads.push(decoded);
            }
        }
    }
    if lowered.contains("xxd") {
        for found in HEX_LITERAL_PATTERN.find_iter(command_text).flatten() {
            if let Some(decoded) = decode_hex_literal(found.as_str()) {
                payloads.push(decoded);
            }
        }
    }
    payloads
}

/// `_looks_like_read_only_shell_pipeline`.
pub(crate) fn looks_like_read_only_shell_pipeline(
    command_text: &str,
    parts: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    destructive: DestructiveCheck<'_>,
) -> bool {
    if ["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| command_text.contains(marker))
    {
        return false;
    }
    let pipelines = iter_shell_pipelines(parts);
    if pipelines.len() != 1 || pipelines[0].len() < 2 {
        return false;
    }
    pipelines[0]
        .iter()
        .all(|segment| pipeline_segment_is_read_only(segment, cwd, home_dir, destructive))
}

/// `_pipeline_segment_is_read_only`.
pub(crate) fn pipeline_segment_is_read_only(
    segment: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    destructive: DestructiveCheck<'_>,
) -> bool {
    let (Some(command_name), Some(_)) = shell_segment_primary_command(segment) else {
        return false;
    };
    if is_python_interpreter_command(&command_name) {
        let scripts = script_interpreter_texts(segment);
        return !scripts.is_empty()
            && scripts
                .iter()
                .all(|script| script_is_read_only_observer(script));
    }
    !destructive(&segment.join(" "), cwd, home_dir)
}
