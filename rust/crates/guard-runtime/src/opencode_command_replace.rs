//! `opencode_command_replace`: swap one OpenCode MCP launcher's `command`
//! array in the config text, leaving every other byte as the user wrote it.
//!
//! Refreshing a Guard-managed launcher only changes its CLI prefix, so the
//! file is edited in place rather than rewritten: the comments, spacing and
//! member order around `mcp.<name>.command` stay untouched. Comments inside
//! the replaced array are kept as notes, one per line, before the new value.
//!
//! The member is found by walking the comment-masked text the way
//! `json.JSONDecoder.raw_decode` did: each of `mcp`, `<name>` and `command`
//! must appear exactly once in its object. A missing, repeated or malformed member answers
//! a reason instead of a text, and the caller leaves the file unchanged.
//!
//! Offsets count characters, as Python's do, so a comment holding non-ASCII
//! text before the member does not move the edit. The new array is spelled as
//! Python's `json.dumps` spells a list of strings.

use guard_command::jsonc::normalize_jsonc;
use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// Arguments one launcher command may carry.
const MAX_COMMAND_PARTS: usize = 4096;

const INVALID_CONFIG: &str = "Invalid OpenCode config";
const EXPECTED_OBJECT: &str = "OpenCode launcher refresh expected an object";
const INVALID_MEMBER: &str = "Invalid OpenCode object member";
const INVALID_SEPARATOR: &str = "Invalid OpenCode object separator";
const MISSING_MEMBER: &str = "OpenCode launcher member is missing or ambiguous";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let text = args
        .get("text")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let command = args
        .get("command")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if command.len() > MAX_COMMAND_PARTS {
        return Err(ERR_INVALID);
    }
    let command = command
        .iter()
        .map(|part| part.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(match replace_command(text, name, &command) {
        Ok(text) => json!({ "text": text }),
        Err(reason) => json!({ "text": null, "reason": reason }),
    })
}

/// `_replace_command`: `text` with `mcp.<name>.command` set to `command`.
fn replace_command(text: &str, name: &str, command: &[&str]) -> Result<String, &'static str> {
    let normalized = normalize_jsonc(text).map_err(|_| INVALID_CONFIG)?;
    let mut span = (0, normalized.len());
    for key in ["mcp", name, "command"] {
        span = member_span(&normalized, span.0, key)?;
    }
    let start = byte_offset(text, normalized[..span.0].chars().count());
    let end = byte_offset(text, normalized[..span.1].chars().count());
    let mut replaced = String::with_capacity(text.len());
    replaced.push_str(&text[..start]);
    replaced.push_str(&comment_notes(&text[start..end])?);
    replaced.push_str(&python_json_list(command));
    replaced.push_str(&text[end..]);
    Ok(replaced)
}

/// The byte offset of the `chars`th character of `text`.
fn byte_offset(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map_or(text.len(), |(index, _)| index)
}

/// JSON's own whitespace; the masked text has nothing else between tokens.
fn skip(text: &str, mut index: usize) -> usize {
    let bytes = text.as_bytes();
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        index += 1;
    }
    index
}

/// The byte offset just past the string token that opens at `index`.
fn skip_string(bytes: &[u8], mut index: usize) -> Result<usize, &'static str> {
    index += 1;
    loop {
        match bytes.get(index) {
            Some(b'"') => return Ok(index + 1),
            Some(b'\\') => index += 2,
            Some(_) => index += 1,
            None => return Err(INVALID_CONFIG),
        }
    }
}

/// The byte offset just past the JSON value that starts at `index`.
///
/// The caller has already parsed the whole document with Python's `json`, so
/// this only finds where a value ends: strings and brackets are matched and a
/// scalar runs to the next delimiter. Values Python accepts and a strict
/// parser would not, such as `NaN`, lone surrogate escapes or deep nesting,
/// are passed over like any other.
fn skip_value(text: &str, index: usize) -> Result<usize, &'static str> {
    let bytes = text.as_bytes();
    match bytes.get(index) {
        Some(b'"') => skip_string(bytes, index),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut at = index;
            loop {
                match bytes.get(at) {
                    Some(b'"') => {
                        at = skip_string(bytes, at)?;
                        continue;
                    }
                    Some(b'{' | b'[') => depth += 1,
                    Some(b'}' | b']') => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(at + 1);
                        }
                    }
                    Some(_) => {}
                    None => return Err(INVALID_CONFIG),
                }
                at += 1;
            }
        }
        _ => {
            let end = bytes[index..]
                .iter()
                .position(|byte| {
                    matches!(
                        byte,
                        b',' | b'}' | b']' | b':' | b' ' | b'\t' | b'\n' | b'\r'
                    )
                })
                .map_or(bytes.len(), |offset| index + offset);
            if end == index {
                Err(INVALID_CONFIG)
            } else {
                Ok(end)
            }
        }
    }
}

/// `_member_span`: the byte span of the value of `key` in the object that
/// starts at `offset`, which must name it exactly once.
fn member_span(text: &str, offset: usize, key: &str) -> Result<(usize, usize), &'static str> {
    let bytes = text.as_bytes();
    let mut index = skip(text, offset);
    if bytes.get(index) != Some(&b'{') {
        return Err(EXPECTED_OBJECT);
    }
    index = skip(text, index + 1);
    let mut found = Vec::new();
    while bytes.get(index) != Some(&b'}') {
        if bytes.get(index) != Some(&b'"') {
            return Err(INVALID_MEMBER);
        }
        let end = skip_string(bytes, index)?;
        // A name that does not decode, such as one holding a lone surrogate
        // escape, cannot equal `key`.
        let matches =
            serde_json::from_str::<String>(&text[index..end]).is_ok_and(|name| name == key);
        let colon = skip(text, end);
        if bytes.get(colon) != Some(&b':') {
            return Err(INVALID_MEMBER);
        }
        let start = skip(text, colon + 1);
        let end = skip_value(text, start)?;
        if matches {
            found.push((start, end));
        }
        index = skip(text, end);
        match bytes.get(index) {
            Some(b'}') => break,
            Some(b',') => index = skip(text, index + 1),
            _ => return Err(INVALID_SEPARATOR),
        }
    }
    match found.as_slice() {
        [span] => Ok(*span),
        _ => Err(MISSING_MEMBER),
    }
}

/// The comments inside the replaced value, each ended by a line break, so
/// none is lost with the old array.
fn comment_notes(old: &str) -> Result<String, &'static str> {
    let masked: Vec<char> = normalize_jsonc(old)
        .map_err(|_| INVALID_CONFIG)?
        .chars()
        .collect();
    let old: Vec<char> = old.chars().collect();
    let opens = |index: usize, marker: char| {
        old.get(index) == Some(&'/')
            && old.get(index + 1) == Some(&marker)
            && masked.get(index) == Some(&' ')
            && masked.get(index + 1) == Some(&' ')
    };
    let mut notes = String::new();
    let mut index = 0;
    while index < old.len() {
        let stop = if opens(index, '/') {
            (index..old.len())
                .find(|&at| old[at] == '\n')
                .unwrap_or(old.len())
        } else if opens(index, '*') {
            (index + 2..old.len().saturating_sub(1))
                .find(|&at| old[at] == '*' && old[at + 1] == '/')
                .map(|at| at + 2)
                .ok_or(INVALID_CONFIG)?
        } else {
            index += 1;
            continue;
        };
        notes.extend(&old[index..stop]);
        notes.push('\n');
        index = stop;
    }
    Ok(notes)
}

/// `json.dumps(list_of_strings)`: `", "` between items, and every character
/// outside printable ASCII escaped, astral ones as a surrogate pair.
fn python_json_list(parts: &[&str]) -> String {
    let mut out = String::from("[");
    for (position, part) in parts.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        out.push('"');
        for character in part.chars() {
            match character {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                ' '..='~' => out.push(character),
                _ => {
                    let mut units = [0u16; 2];
                    for unit in character.encode_utf16(&mut units) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

#[cfg(test)]
#[path = "opencode_command_replace_tests.rs"]
mod tests;
