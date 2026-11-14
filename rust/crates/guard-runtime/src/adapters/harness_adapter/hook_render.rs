//! `render_hook_command`: the command line Codex and Cursor hand a hook to the
//! session shell.
//!
//! POSIX hosts get `shlex.join`. A Windows command must parse the same way in
//! PowerShell and `cmd.exe`, so it uses plain tokens only, replacing a path
//! that would need quoting by its 8.3 short name when that name is itself a
//! plain token and maps back to exactly that path. Only the Windows host can
//! name the short form, so a path without one in `short_names` is asked for
//! with `{"reply": {"shorten": [...]}}` and the host answers each with
//! `[short, long_of_short]`. Without a plain form the command falls back to
//! PowerShell's call operator with single-quoted literals.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

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

/// The reply asking the host for `paths`' short names.
pub(super) fn ask_for(paths: BTreeSet<String>) -> Failure {
    Failure::Reply(json!({ "shorten": paths }))
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

fn powershell_literal(argument: &str) -> String {
    format!("'{}'", argument.replace('\'', "''"))
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
