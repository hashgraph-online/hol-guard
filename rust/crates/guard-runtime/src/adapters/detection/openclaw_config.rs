//! OpenClaw configuration loading for `openclaw_detect`, mirroring the
//! original `openclaw_config.load_config`: the file is read as JSON, then
//! with comments and trailing commas stripped, then as JSON5 with bare keys
//! and single-quoted strings; `$include` files merge underneath the local
//! settings, eight levels deep and never through a file already on the
//! include chain. Anything unreadable or not an object is an empty
//! configuration. Input CPython raises on instead of parsing (nesting past
//! the recursion limit, an oversized integer) is refused.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::aibom_paths::resolve;
use super::aibom_skill_rules::expanduser;
use super::context_digest::python_strip;
use super::pyjson::{parse_marking_lone_surrogates, JsonFailure, PyVal};
use super::runner_authority_op::ERR_INVALID;

const MAX_INCLUDE_DEPTH: usize = 8;
const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;
const CONFIG_SUFFIXES: [&str; 4] = ["json", "json5", "yaml", "yml"];

type Entries = Vec<(String, PyVal)>;

/// `load_config(path)`: the merged configuration object. `user_home` is the
/// home Python's `expanduser` would use for an include spelled with `~`.
pub(crate) fn load(path: &Path, user_home: Option<&str>) -> Result<PyVal, &'static str> {
    load_at(path, &[], 0, user_home).map(PyVal::Dict)
}

fn load_at(
    path: &Path,
    seen: &[PathBuf],
    depth: usize,
    user_home: Option<&str>,
) -> Result<Entries, &'static str> {
    if depth > MAX_INCLUDE_DEPTH {
        return Ok(Vec::new());
    }
    let Ok(resolved) = resolve(path) else {
        return Ok(Vec::new());
    };
    if seen.contains(&resolved) {
        return Ok(Vec::new());
    }
    let Some(raw) = read_text(&resolved) else {
        return Ok(Vec::new());
    };
    let PyVal::Dict(payload) = parse_config_payload(&raw)? else {
        return Ok(Vec::new());
    };
    let mut chain = seen.to_vec();
    chain.push(resolved.clone());
    let base_dir = resolved.parent().unwrap_or(&resolved);
    let mut merged = Vec::new();
    let include = payload.iter().find(|(key, _)| key == "$include");
    for include_path in include_paths(base_dir, include.map(|(_, value)| value), user_home) {
        let included = load_at(&include_path, &chain, depth + 1, user_home)?;
        merged = deep_merge(merged, included);
    }
    let local = payload
        .into_iter()
        .filter(|(key, _)| key != "$include")
        .collect();
    Ok(deep_merge(merged, local))
}

/// `Path.read_text(encoding="utf-8")`: strict UTF-8 with universal newlines.
/// A non-regular or oversized file is unreadable.
fn read_text(path: &Path) -> Option<String> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `_include_paths`: each non-blank string with a config suffix, relative to
/// the including file's resolved directory.
fn include_paths(base_dir: &Path, value: Option<&PyVal>, user_home: Option<&str>) -> Vec<PathBuf> {
    let values: Vec<&PyVal> = match value {
        Some(PyVal::List(items)) => items.iter().collect(),
        Some(other) => vec![other],
        None => vec![&PyVal::Null],
    };
    values
        .into_iter()
        .filter_map(|item| {
            let stripped = python_strip(item.as_str()?);
            if stripped.is_empty() {
                return None;
            }
            let candidate = expanduser(stripped, user_home);
            let path = if candidate.is_absolute() {
                candidate
            } else {
                base_dir.join(candidate)
            };
            let suffix = path.extension()?.to_str()?.to_lowercase();
            CONFIG_SUFFIXES.contains(&suffix.as_str()).then_some(path)
        })
        .collect()
}

/// `_deep_merge`: nested objects merge; any other value replaces the base's,
/// keeping the base's key position.
fn deep_merge(base: Entries, overlay: Entries) -> Entries {
    let mut result = base;
    for (key, value) in overlay {
        match result.iter_mut().find(|(name, _)| *name == key) {
            Some(slot) => {
                slot.1 = match (std::mem::replace(&mut slot.1, PyVal::Null), value) {
                    (PyVal::Dict(existing), PyVal::Dict(value)) => {
                        PyVal::Dict(deep_merge(existing, value))
                    }
                    (_, value) => value,
                }
            }
            None => result.push((key, value)),
        }
    }
    result
}

/// `json.loads(text)`: `None` for a `JSONDecodeError`.
fn attempt(text: &str) -> Result<Option<PyVal>, &'static str> {
    match parse_marking_lone_surrogates(text) {
        Ok(value) => Ok(Some(value)),
        Err(JsonFailure::Syntax) => Ok(None),
        Err(_) => Err(ERR_INVALID),
    }
}

/// `_parse_config_payload`.
fn parse_config_payload(raw: &str) -> Result<PyVal, &'static str> {
    if let Some(value) = attempt(raw)? {
        return Ok(value);
    }
    let stripped = strip_comments(raw);
    if let Some(value) = attempt(&strip_trailing_commas(&stripped))? {
        return Ok(value);
    }
    let json5 = strip_trailing_commas(&convert_single_quoted_strings(&quote_unquoted_keys(
        &stripped,
    )));
    Ok(attempt(&json5)?.unwrap_or(PyVal::Dict(Vec::new())))
}

/// Tracks a quoted string, `quote` set while inside one.
#[derive(Default)]
struct Quoted {
    quote: Option<char>,
    escape: bool,
}

impl Quoted {
    /// Feeds `char` while inside a string; it is copied unchanged.
    fn inside(&mut self, char: char) {
        if self.escape {
            self.escape = false;
        } else if char == '\\' {
            self.escape = true;
        } else if Some(char) == self.quote {
            self.quote = None;
        }
    }
}

/// `strip_jsonc_comments(text, string_quotes=SINGLE_AND_DOUBLE_QUOTE)`:
/// `//` and `/* */` comments go, newlines inside them stay.
fn strip_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut quoted = Quoted::default();
    let (mut line_comment, mut block_comment) = (false, false);
    let mut index = 0;
    while index < chars.len() {
        let char = chars[index];
        let next = chars.get(index + 1).copied();
        if line_comment {
            if char == '\n' {
                line_comment = false;
                output.push(char);
            }
            index += 1;
            continue;
        }
        if block_comment {
            if char == '*' && next == Some('/') {
                block_comment = false;
                index += 2;
                continue;
            }
            if char == '\n' {
                output.push(char);
            }
            index += 1;
            continue;
        }
        if quoted.quote.is_some() {
            output.push(char);
            quoted.inside(char);
            index += 1;
            continue;
        }
        if char == '\'' || char == '"' {
            quoted.quote = Some(char);
            output.push(char);
            index += 1;
            continue;
        }
        if char == '/' && (next == Some('/') || next == Some('*')) {
            line_comment = next == Some('/');
            block_comment = next == Some('*');
            index += 2;
            continue;
        }
        output.push(char);
        index += 1;
    }
    output
}

/// `_strip_trailing_json_commas`: a comma followed only by JSON whitespace
/// and a closing bracket goes.
fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut quoted = Quoted::default();
    for (index, &char) in chars.iter().enumerate() {
        if quoted.quote.is_some() {
            output.push(char);
            quoted.inside(char);
            continue;
        }
        if char == '\'' || char == '"' {
            quoted.quote = Some(char);
        } else if char == ',' {
            let closes = chars[index + 1..]
                .iter()
                .find(|next| !matches!(next, ' ' | '\t' | '\r' | '\n'))
                .is_some_and(|next| matches!(next, '}' | ']'));
            if closes {
                continue;
            }
        }
        output.push(char);
    }
    output
}

/// `[A-Za-z_$][A-Za-z0-9_$-]*` at the start of `chars`, by length.
fn identifier_len(chars: &[char]) -> usize {
    match chars.first() {
        Some(first) if first.is_ascii_alphabetic() || matches!(first, '_' | '$') => {
            1 + chars[1..]
                .iter()
                .take_while(|char| char.is_ascii_alphanumeric() || matches!(char, '_' | '$' | '-'))
                .count()
        }
        _ => 0,
    }
}

/// `_quote_unquoted_object_keys`: a bare identifier after `{` or `,` and
/// before `:` becomes a JSON string. Only an ASCII identifier start can
/// match, so the Unicode `isalpha` test in front of the pattern changes
/// nothing.
fn quote_unquoted_keys(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut quoted = Quoted::default();
    let mut expecting_key = false;
    let mut index = 0;
    while index < chars.len() {
        let char = chars[index];
        if quoted.quote.is_some() {
            output.push(char);
            quoted.inside(char);
            index += 1;
            continue;
        }
        if char == '\'' || char == '"' {
            quoted.quote = Some(char);
            output.push(char);
            index += 1;
            continue;
        }
        if char == '{' || char == ',' {
            expecting_key = true;
            output.push(char);
            index += 1;
            continue;
        }
        if expecting_key && char.is_whitespace() {
            output.push(char);
            index += 1;
            continue;
        }
        if expecting_key {
            let length = identifier_len(&chars[index..]);
            if length > 0 {
                let colon = chars[index + length..]
                    .iter()
                    .find(|next| !next.is_whitespace())
                    .is_some_and(|next| *next == ':');
                if colon {
                    output.push('"');
                    output.extend(&chars[index..index + length]);
                    output.push('"');
                    index += length;
                    expecting_key = false;
                    continue;
                }
            }
        }
        expecting_key = false;
        output.push(char);
        index += 1;
    }
    output
}

/// `_convert_single_quoted_strings`: a single-quoted string becomes a JSON
/// string, re-escaping the characters JSON reads differently.
fn convert_single_quoted_strings(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut escape = false;
    for char in text.chars() {
        match quote {
            Some('\'') => {
                if escape {
                    match char {
                        '\'' => output.push('\''),
                        '"' => output.push_str("\\\""),
                        '\\' => output.push_str("\\\\"),
                        'b' | 'f' | 'n' | 'r' | 't' | '/' => {
                            output.push('\\');
                            output.push(char);
                        }
                        _ => output.push(char),
                    }
                    escape = false;
                } else if char == '\\' {
                    escape = true;
                } else if char == '\'' {
                    quote = None;
                    output.push('"');
                } else if char == '"' {
                    output.push_str("\\\"");
                } else {
                    output.push(char);
                }
            }
            Some(_) => {
                output.push(char);
                if escape {
                    escape = false;
                } else if char == '\\' {
                    escape = true;
                } else if char == '"' {
                    quote = None;
                }
            }
            None => {
                if char == '\'' {
                    quote = Some('\'');
                    output.push('"');
                    continue;
                }
                if char == '"' {
                    quote = Some('"');
                }
                output.push(char);
            }
        }
    }
    output
}
