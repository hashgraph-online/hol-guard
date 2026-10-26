//! Port of `hook_execution_environment.py` (`stamp_hook_input_text`) and
//! `codex_daemon_hook_transport.py::_with_remaining_hint` for the native
//! Claude hook bridge.
//!
//! Both rewrite the hook input the way CPython's `json.loads` + `json.dumps`
//! would: object members keep their first position, numbers keep their
//! CPython text, and strings are escaped exactly as `ensure_ascii` selects.
//! A lone surrogate CPython would keep in a `str` (from a `\uXXXX` escape or
//! a non-UTF-8 environment byte) is carried as a private-use character from
//! [`pyjson::SURROGATE_PLANE_BASE`] and written back as its `\udXXX` escape.
//! When the input or environment already holds a genuine character from that
//! range the two can no longer be told apart, and the stamp is refused
//! rather than guessed.

use std::ffi::OsString;
use std::sync::OnceLock;

use regex::Regex;

use crate::guard_store_wfcap_frame::sha256_hex;
use crate::pyjson::{self, in_surrogate_plane, JsonFailure, PyVal, SURROGATE_PLANE_BASE};

pub(crate) const HOOK_EXECUTION_ENVIRONMENT_KEY: &str = "guard_execution_environment";
pub(crate) const MAX_STAMPED_HOOK_INPUT_BYTES: usize = 1_000_000;
const PAGER_NAMES: [&str; 2] = ["GIT_PAGER", "PAGER"];
const GIT_TRUE_VALUES: [&str; 4] = ["1", "true", "yes", "on"];
const LIBRARY_SEARCH_PATH_NAMES: [&str; 5] = [
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
];
const MAX_STAMPED_PATH_BYTES: usize = 32 * 1024;
const MAX_REMAINING_HINT_MS: u128 = 60_000;

/// Result of stamping hook input with the execution environment.
#[derive(Debug, PartialEq)]
pub(crate) enum Stamp {
    /// The text to forward: stamped, or the input unchanged where CPython
    /// would have forwarded it unchanged.
    Text(String),
    /// Input CPython would have crashed on (nesting past its recursion
    /// limit), or that cannot be re-serialized byte for byte.
    Unrepresentable,
}

/// The process environment as CPython's `os.environ` decodes it: names and
/// values in a `Vec`, plus whether any lone surrogate was mapped and whether
/// a genuine character from the mapped range was seen.
pub(crate) struct DecodedEnvironment {
    pub(crate) entries: Vec<(String, String)>,
    pub(crate) mapped: bool,
    pub(crate) collision: bool,
}

pub(crate) fn current_environment() -> DecodedEnvironment {
    decode_environment(std::env::vars_os())
}

pub(crate) fn decode_environment(
    variables: impl IntoIterator<Item = (OsString, OsString)>,
) -> DecodedEnvironment {
    let mut decoded = DecodedEnvironment {
        entries: Vec::new(),
        mapped: false,
        collision: false,
    };
    for (name, value) in variables {
        let name = decode_os(&name, &mut decoded);
        let value = decode_os(&value, &mut decoded);
        // CPython's `convertenviron` keeps the first duplicate of a name.
        if !decoded.entries.iter().any(|(key, _)| *key == name) {
            decoded.entries.push((name, value));
        }
    }
    decoded
}

#[cfg(unix)]
fn decode_os(text: &std::ffi::OsStr, flags: &mut DecodedEnvironment) -> String {
    use std::os::unix::ffi::OsStrExt;
    // `surrogateescape`: each byte of an invalid sequence becomes U+DC00+byte.
    let mut out = String::new();
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                push_checked(&mut out, valid, flags);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                push_checked(
                    &mut out,
                    std::str::from_utf8(&rest[..valid]).unwrap_or_default(),
                    flags,
                );
                let bad = error.error_len().unwrap_or(rest.len() - valid);
                for byte in &rest[valid..valid + bad] {
                    out.push(surrogate_char(0xdc00 + u32::from(*byte)));
                    flags.mapped = true;
                }
                rest = &rest[valid + bad..];
            }
        }
    }
    out
}

#[cfg(unix)]
fn push_checked(out: &mut String, valid: &str, flags: &mut DecodedEnvironment) {
    if valid.chars().any(in_surrogate_plane) {
        flags.collision = true;
    }
    out.push_str(valid);
}

#[cfg(not(unix))]
fn decode_os(text: &std::ffi::OsStr, flags: &mut DecodedEnvironment) -> String {
    use std::os::windows::ffi::OsStrExt;
    let mut out = String::new();
    for unit in char::decode_utf16(text.encode_wide()) {
        match unit {
            Ok(character) => {
                if in_surrogate_plane(character) {
                    flags.collision = true;
                }
                out.push(character);
            }
            Err(error) => {
                flags.mapped = true;
                out.push(surrogate_char(u32::from(error.unpaired_surrogate())));
            }
        }
    }
    out
}

fn surrogate_char(surrogate: u32) -> char {
    char::from_u32(SURROGATE_PLANE_BASE + surrogate - 0xd800).unwrap_or(char::REPLACEMENT_CHARACTER)
}

fn lookup<'a>(environment: &'a DecodedEnvironment, name: &str) -> Option<&'a str> {
    environment
        .entries
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn pager_default_equivalent(value: Option<&str>) -> bool {
    static PAGER: OnceLock<Regex> = OnceLock::new();
    let pattern = PAGER.get_or_init(|| {
        Regex::new(r"^(?:cat|less(?: -[ABCEFGIJKLMNQRSUVWXacdefgimnqrsuw~]+)*)?$")
            .expect("pager pattern compiles")
    });
    value.is_some_and(|value| pattern.is_match(value))
}

fn git_config_no_system_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        let folded = caseless::default_case_fold_str(value);
        GIT_TRUE_VALUES.contains(&folded.as_str())
    })
}

/// CPython orders `str` by code point; a mapped surrogate sorts as the
/// surrogate it stands for.
fn py_order_key(text: &str, unmap: bool) -> Vec<u32> {
    text.chars()
        .map(|c| {
            if unmap && in_surrogate_plane(c) {
                c as u32 - SURROGATE_PLANE_BASE + 0xd800
            } else {
                c as u32
            }
        })
        .collect()
}

/// `collect_hook_execution_environment()` for `environment`.
pub(crate) fn collect_hook_execution_environment(environment: &DecodedEnvironment) -> PyVal {
    let unmap = environment.mapped;
    let mut active: Vec<(String, String)> = Vec::new();
    for (name, value) in &environment.entries {
        if !value.is_empty() {
            active.push((name.clone(), value.clone()));
        }
    }
    active.sort_by_cached_key(|(key, _)| py_order_key(key, unmap));
    let mut names: Vec<String> = active.iter().map(|(key, _)| key.clone()).collect();
    for pager in PAGER_NAMES {
        if lookup(environment, pager).is_some() && !names.iter().any(|name| name == pager) {
            names.push(pager.to_owned());
        }
    }
    names.sort_by_cached_key(|name| py_order_key(name, unmap));

    let library_paths = LIBRARY_SEARCH_PATH_NAMES
        .iter()
        .filter_map(|name| {
            let value = lookup(environment, name)?;
            let has_surrogate = unmap && value.chars().any(in_surrogate_plane);
            (!value.is_empty() && !has_surrogate && value.len() <= MAX_STAMPED_PATH_BYTES)
                .then(|| ((*name).to_owned(), PyVal::Str(value.to_owned())))
        })
        .collect();

    let digest_input = PyVal::Dict(
        active
            .into_iter()
            .map(|(key, value)| (key, PyVal::Str(value)))
            .collect(),
    );
    let mut digest_text = String::new();
    dumps(&digest_input, true, unmap, &mut digest_text);

    let optional = |value: Option<&str>| match value {
        Some(value) => PyVal::Str(value.to_owned()),
        None => PyVal::Null,
    };
    PyVal::Dict(vec![
        (
            "path".to_owned(),
            PyVal::Str(lookup(environment, "PATH").unwrap_or_default().to_owned()),
        ),
        ("home".to_owned(), optional(lookup(environment, "HOME"))),
        (
            "git_pager_disabled".to_owned(),
            PyVal::Bool(pager_default_equivalent(lookup(environment, "GIT_PAGER"))),
        ),
        (
            "pager_disabled".to_owned(),
            PyVal::Bool(pager_default_equivalent(lookup(environment, "PAGER"))),
        ),
        (
            "environment_names".to_owned(),
            PyVal::List(names.into_iter().map(PyVal::Str).collect()),
        ),
        (
            "xdg_config_home".to_owned(),
            optional(lookup(environment, "XDG_CONFIG_HOME").filter(|value| !value.is_empty())),
        ),
        (
            "git_config_no_system".to_owned(),
            PyVal::Bool(git_config_no_system_enabled(lookup(
                environment,
                "GIT_CONFIG_NOSYSTEM",
            ))),
        ),
        (
            "library_search_paths".to_owned(),
            PyVal::Dict(library_paths),
        ),
        (
            "environment_digest".to_owned(),
            PyVal::Str(sha256_hex(digest_text.as_bytes())),
        ),
    ])
}

/// `stamp_hook_input_text(text)` against `environment`.
pub(crate) fn stamp_hook_input_text(text: &str, environment: &DecodedEnvironment) -> Stamp {
    let parsed = match pyjson::parse_mapping_lone_surrogates(text) {
        Ok(parsed) => parsed,
        Err(JsonFailure::Unrepresentable) => return Stamp::Unrepresentable,
        Err(_) => return Stamp::Text(text.to_owned()),
    };
    let PyVal::Dict(mut entries) = parsed.value else {
        return Stamp::Text(text.to_owned());
    };
    let mapped = parsed.mapped || environment.mapped;
    if mapped && (parsed.collision || environment.collision) {
        return Stamp::Unrepresentable;
    }
    set_member(
        &mut entries,
        HOOK_EXECUTION_ENVIRONMENT_KEY,
        collect_hook_execution_environment(environment),
    );
    let mut stamped = String::new();
    dumps(&PyVal::Dict(entries), true, mapped, &mut stamped);
    if stamped.len() > MAX_STAMPED_HOOK_INPUT_BYTES {
        Stamp::Text(text.to_owned())
    } else {
        Stamp::Text(stamped)
    }
}

/// `_with_remaining_hint(data, deadline)`: `Err` where CPython's `json.loads`
/// raises something other than `JSONDecodeError` (a `ValueError` the bridge
/// classifies as an authenticated control-plane failure).
pub(crate) fn with_remaining_hint(data: &str, remaining_ms: u128) -> Result<String, JsonFailure> {
    let parsed = match pyjson::parse_mapping_lone_surrogates(data) {
        Ok(parsed) => parsed,
        Err(JsonFailure::Syntax) => return Ok(data.to_owned()),
        Err(failure) => return Err(failure),
    };
    let PyVal::Dict(mut entries) = parsed.value else {
        return Ok(data.to_owned());
    };
    // `ensure_ascii=False` keeps a lone surrogate, which the UTF-8 encode
    // then refuses; CPython falls back to the unhinted text.
    if parsed.mapped {
        return Ok(data.to_owned());
    }
    let hint = remaining_ms.clamp(1, MAX_REMAINING_HINT_MS);
    set_member(
        &mut entries,
        "guard_remaining_ms",
        PyVal::Int(hint.to_string()),
    );
    let mut hinted = String::new();
    dumps(&PyVal::Dict(entries), false, false, &mut hinted);
    if hinted.len() > MAX_STAMPED_HOOK_INPUT_BYTES {
        return Ok(data.to_owned());
    }
    Ok(hinted)
}

pub(crate) fn set_member(entries: &mut Vec<(String, PyVal)>, key: &str, value: PyVal) {
    match entries.iter_mut().find(|(existing, _)| existing == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key.to_owned(), value)),
    }
}

/// `json.dumps(value, ensure_ascii=..., separators=(",", ":"))`, writing a
/// mapped surrogate back as its `\udXXX` escape when `unmap` is set.
pub(crate) fn dumps(value: &PyVal, ensure_ascii: bool, unmap: bool, out: &mut String) {
    match value {
        PyVal::Null => out.push_str("null"),
        PyVal::Bool(true) => out.push_str("true"),
        PyVal::Bool(false) => out.push_str("false"),
        PyVal::Int(digits) => out.push_str(digits),
        PyVal::Float(number) => out.push_str(&float_text(*number)),
        PyVal::Str(text) => write_string(text, ensure_ascii, unmap, out),
        PyVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                dumps(item, ensure_ascii, unmap, out);
            }
            out.push(']');
        }
        PyVal::Dict(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, ensure_ascii, unmap, out);
                out.push(':');
                dumps(item, ensure_ascii, unmap, out);
            }
            out.push('}');
        }
    }
}

fn float_text(number: f64) -> String {
    if number.is_nan() {
        "NaN".to_owned()
    } else if number.is_infinite() {
        if number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        }
        .to_owned()
    } else {
        pyjson::float_repr(number)
    }
}

fn push_unit(out: &mut String, unit: u32) {
    out.push_str(&format!("\\u{unit:04x}"));
}

/// `text` as CPython writes it to stderr (`errors="backslashreplace"`):
/// each mapped lone surrogate as its `\udXXX` escape, the rest as is.
pub(crate) fn backslash_surrogates(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if in_surrogate_plane(character) {
            push_unit(&mut out, character as u32 - SURROGATE_PLANE_BASE + 0xd800);
        } else {
            out.push(character);
        }
    }
    out
}

/// `json.dumps(text, ensure_ascii=...)` for one string.
pub(crate) fn json_string(text: &str, ensure_ascii: bool, unmap: bool) -> String {
    let mut out = String::new();
    write_string(text, ensure_ascii, unmap, &mut out);
    out
}

fn write_string(text: &str, ensure_ascii: bool, unmap: bool, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => push_unit(out, c as u32),
            c if unmap && in_surrogate_plane(c) => {
                push_unit(out, c as u32 - SURROGATE_PLANE_BASE + 0xd800);
            }
            c if !ensure_ascii || (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut units = [0_u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    push_unit(out, u32::from(*unit));
                }
            }
        }
    }
    out.push('"');
}

#[cfg(all(test, unix))]
#[path = "hook_env_stamp_tests.rs"]
pub(crate) mod tests;
