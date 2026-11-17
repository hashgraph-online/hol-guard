//! `render_hook_command`: the command line Codex and Cursor hand a hook to the
//! session shell.
//!
//! POSIX hosts get `shlex.join`. A Windows command must parse the same way in
//! PowerShell and `cmd.exe`, so it uses plain tokens only, replacing a path
//! that would need quoting by its 8.3 short name when that name is itself a
//! plain token and maps back to exactly that path. Only the Windows host can
//! name the short form: the runtime asks its own host for a path the request's
//! `short_names` does not name, and a host with no 8.3 names has none to give.
//! Without a plain form the command falls back to
//! PowerShell's call operator with single-quoted literals.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{Failure, Step};
use crate::cursor_hook_command::is_short_token;

pub(super) const REFUSAL: &str =
    "Codex hook arguments cannot be empty or contain line breaks or NUL on Windows.";

/// What the host said about one path: its 8.3 name and that name's long form.
pub(super) type ShortNames = BTreeMap<String, (Option<String>, Option<String>)>;

/// `[A-Za-z0-9_.:\\/-]+`: a token both Windows shells read literally.
fn is_bare(argument: &str) -> bool {
    !argument.is_empty()
        && argument.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '\\' | '/' | '-')
        })
}

/// `short_names` from the request: `{path: [short | null, long | null]}`.
pub(super) fn short_names(fields: &Map<String, Value>) -> Step<ShortNames> {
    let Some(found) = fields.get("short_names") else {
        return Ok(ShortNames::new());
    };
    let text = |value: &Value| match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(Failure::Invalid),
    };
    found
        .as_object()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|(path, pair)| match pair.as_array().map(Vec::as_slice) {
            Some([short, long]) => Ok((path.clone(), (text(short)?, text(long)?))),
            _ => Err(Failure::Invalid),
        })
        .collect()
}

/// The paths in `argvs` whose short form the host has not yet named.
pub(super) fn unnamed<'a>(
    argvs: impl IntoIterator<Item = &'a [String]>,
    windows: bool,
    names: &ShortNames,
) -> BTreeSet<String> {
    if !windows {
        return BTreeSet::new();
    }
    argvs
        .into_iter()
        .filter(|argv| !refused(argv) && !argv[0].starts_with('-'))
        .flatten()
        .filter(|argument| !is_bare(argument) && !names.contains_key(*argument))
        .cloned()
        .collect()
}

/// `[short, long_of_short]` for `path`, as this Windows host names them.
fn host_name(path: &str) -> (Option<String>, Option<String>) {
    let short = guard_runtime_windows_process::short_path_name(path);
    let long = short
        .as_deref()
        .and_then(guard_runtime_windows_process::long_path_name);
    (short, long)
}

/// The short names every path in `argvs` needs: those the request names,
/// then this host's own answer for the rest. A host with no 8.3 names has no
/// short form to give, so such a path keeps the call operator.
pub(super) fn names_for<'a>(
    fields: &Map<String, Value>,
    argvs: impl IntoIterator<Item = &'a [String]>,
    windows: bool,
) -> Step<ShortNames> {
    let mut names = short_names(fields)?;
    let missing = unnamed(argvs, windows, &names);
    if missing.is_empty() {
        return Ok(names);
    }
    for path in missing {
        let named = host_name(&path);
        names.insert(path, named);
    }
    Ok(names)
}

fn refused(argv: &[String]) -> bool {
    argv.is_empty()
        || argv
            .iter()
            .any(|argument| argument.contains(['\r', '\n', '\0']))
}

/// `_plain_windows_token`: the token both shells read as `argument`.
fn plain(argument: &str, names: &ShortNames) -> Option<String> {
    if is_bare(argument) {
        return Some(argument.to_owned());
    }
    match names.get(argument)? {
        (Some(short), Some(long)) if is_short_token(short) && long == argument => {
            Some(short.clone())
        }
        _ => None,
    }
}

/// A single-quoted PowerShell literal. PowerShell closes such a string on
/// any of its single-quote characters, typographic ones included, so each is
/// doubled.
fn powershell_literal(argument: &str) -> String {
    let mut literal = String::from('\'');
    for ch in argument.chars() {
        if matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            literal.push(ch);
        }
        literal.push(ch);
    }
    literal.push('\'');
    literal
}

/// The command line for `argv`, once every path it needs is in `names`
/// (see [`unnamed`]). A Windows argv no shell can carry is refused.
pub(super) fn render(argv: &[String], windows: bool, names: &ShortNames) -> Step<String> {
    if !windows {
        return Ok(crate::mcp_proxy_shlex::join(argv));
    }
    if refused(argv) {
        return Err(Failure::Refusal(REFUSAL.to_owned()));
    }
    if !argv[0].starts_with('-') {
        let tokens: Option<Vec<String>> =
            argv.iter().map(|argument| plain(argument, names)).collect();
        if let Some(tokens) = tokens {
            return Ok(tokens.join(" "));
        }
    }
    let literals: Vec<String> = argv.iter().map(|a| powershell_literal(a)).collect();
    Ok(format!("& {}", literals.join(" ")))
}

#[cfg(test)]
#[path = "hook_render_tests.rs"]
mod tests;
