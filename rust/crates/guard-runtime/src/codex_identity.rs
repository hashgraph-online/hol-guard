//! `codex_hook_identity.py`: the format- and coordinate-independent identity of
//! one Codex hook handler, and the argv normalization of its command.

use sha2::{Digest, Sha256};

use super::codex_value::{canonical_mapping, canonical_value, Canon, HookVal};
use super::pyjson::LONE_SURROGATE_MARK;

pub(crate) const IDENTITY_SCHEMA: &str = "codex-hook-identity-v1";

/// `_SHELL_SENSITIVE_COMMAND_RE`.
fn shell_sensitive(ch: char) -> bool {
    matches!(
        ch,
        '\\' | '\''
            | '"'
            | '`'
            | '$'
            | '|'
            | '&'
            | ';'
            | '<'
            | '>'
            | '('
            | ')'
            | '{'
            | '}'
            | '['
            | ']'
            | '*'
            | '?'
            | '!'
            | '~'
            | '#'
            | '\r'
            | '\n'
    )
}

/// `canonical_codex_command_argv`: a command with no quoting, escaping,
/// expansion or control syntax tokenizes (`shlex.split`) on blanks alone.
pub(crate) fn command_argv(command: Option<&str>) -> Option<Vec<String>> {
    let command = command?;
    if command.chars().any(shell_sensitive) {
        return None;
    }
    let argv: Vec<String> = command
        .split([' ', '\t'])
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect();
    (!argv.is_empty()).then_some(argv)
}

/// `_canonical_command`.
fn canonical_command(command: &str) -> Canon {
    match command_argv(Some(command)) {
        Some(argv) => Canon::object(vec![
            ("mode", Canon::text("argv")),
            (
                "argv",
                Canon::List(argv.into_iter().map(Canon::Str).collect()),
            ),
        ]),
        None => Canon::object(vec![
            ("mode", Canon::text("shell")),
            ("text", Canon::text(command)),
        ]),
    }
}

/// `_canonical_handler`.
fn canonical_handler(handler: &[(String, HookVal)]) -> Canon {
    let Canon::Obj(mut values) = canonical_mapping(handler, &["command"]) else {
        return Canon::Null;
    };
    let command = match handler.iter().find(|(key, _)| key == "command") {
        Some((_, HookVal::Str(text))) => canonical_command(text),
        Some((_, other)) => canonical_value(other),
        None => Canon::Null,
    };
    values.push(("command".to_owned(), command));
    Canon::Obj(values)
}

/// `canonical_codex_hook_identity`. `None` when the hook carries a lone
/// surrogate, which CPython keeps in the value but cannot encode when it
/// hashes the canonical JSON, so the detection fails there.
pub(crate) fn hook_identity(
    source_scope: &str,
    source_hooks_enabled: bool,
    event_name: &str,
    group: &[(String, HookVal)],
    handler: &[(String, HookVal)],
) -> Option<String> {
    let matcher = group
        .iter()
        .find(|(key, _)| key == "matcher")
        .map_or(Canon::Null, |(_, value)| canonical_value(value));
    let payload = Canon::object(vec![
        ("schema", Canon::text(IDENTITY_SCHEMA)),
        ("source_scope", Canon::text(source_scope)),
        ("source_hooks_enabled", Canon::Bool(source_hooks_enabled)),
        ("event", Canon::text(event_name)),
        ("matcher", matcher),
        ("group", canonical_mapping(group, &["hooks", "matcher"])),
        ("handler", canonical_handler(handler)),
    ]);
    let mut text = String::new();
    payload.write(&mut text);
    if text.contains(LONE_SURROGATE_MARK) {
        return None;
    }
    Some(hex::encode(Sha256::digest(text.as_bytes())))
}
