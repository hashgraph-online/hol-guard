//! `copilot-hook-commands --stdin`: which Copilot hook commands Guard wrote,
//! so a reinstall or uninstall replaces its own entries and keeps the user's
//! (`_is_managed_hook_command` in `guard/adapters/copilot.py` before it moved
//! here).
//!
//! A command is Guard's when it is the legacy `python -m
//! codex_plugin_scanner.cli guard hook --harness copilot` spelling, the frozen
//! `__guard-bounded-hook` launcher, the isolated `python -I <script>` bridge
//! at the current Guard home, or an inline `python -c` bridge whose Guard argv
//! targets the Copilot harness. A native `bounded-hook-bridge` prefix wraps
//! the same argv.

use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use guard_command::hook_adapter_value::{parse_python_json, OValue};
use regex::Regex;
use serde::Deserialize;
use serde_json::json;

use crate::harness_coverage::resolve_lenient;
use crate::local_mcp_grant_identity::shlex_split;

const COMMAND: &str = "copilot-hook-commands";
const SCHEMA: &str = "copilot-hook-commands.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_COMMANDS: usize = 1024;
const NATIVE_BOUNDED_HOOK_COMMAND: &str = "bounded-hook-bridge";
const FROZEN_EXECUTABLES: [&str; 3] = ["hol guard", "hol-guard", "hol-guard.exe"];
const INTERPRETER_FLAGS: [&str; 7] = ["-B", "-E", "-I", "-P", "-S", "-s", "-u"];

static LEGACY_PATTERNS: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        r#"(^|["\s])-m["\s]+codex_plugin_scanner\.cli(["\s]|$)"#,
        r#"(^|["\s])guard(["\s]|$)"#,
        r#"(^|["\s])hook(["\s]|$)"#,
        r#"--harness(?:["\s=]+)copilot(["\s]|$)"#,
    ]
    .map(|pattern| Regex::new(pattern).expect("legacy Copilot hook pattern"))
});
static INLINE_ARGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"json\.loads\(('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\)"#)
        .expect("inline Guard argv pattern")
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    commands: Vec<String>,
    /// The isolated interpreter and bridge script Guard installs at the
    /// current Guard home; without both no `python -I` command is Guard's.
    #[serde(default)]
    interpreter: Option<String>,
    #[serde(default)]
    script: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "copilot_hook_commands_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("copilot_hook_commands_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .ok()
        .filter(|request: &Request| {
            request.schema == SCHEMA && request.commands.len() <= MAX_COMMANDS
        })
        .ok_or_else(|| "copilot_hook_commands_request_invalid".to_owned())?;
    let bridge = request
        .interpreter
        .as_deref()
        .zip(request.script.as_deref());
    let managed: Vec<bool> = request
        .commands
        .iter()
        .map(|command| is_managed(command, bridge))
        .collect();
    serde_json::to_vec(&json!({ "managed": managed }))
        .map_err(|_| "copilot_hook_commands_response_unencodable".to_owned())
}

/// Whether Guard wrote `command`; `bridge` is the current `(interpreter,
/// script)` pair of the isolated bridge.
fn is_managed(command: &str, bridge: Option<(&str, &str)>) -> bool {
    let lowered = command.to_lowercase();
    if LEGACY_PATTERNS
        .iter()
        .all(|pattern| pattern.is_match(&lowered))
    {
        return true;
    }
    let Some(mut tokens) = shlex_split(command) else {
        return false;
    };
    if tokens.len() > 2 && !tokens[0].is_empty() && tokens[1] == NATIVE_BOUNDED_HOOK_COMMAND {
        tokens = tokens.split_off(2);
    }
    match tokens.as_slice() {
        [launcher, marker, config] if marker == "__guard-bounded-hook" => {
            FROZEN_EXECUTABLES.contains(&file_name(launcher).to_lowercase().as_str())
                && config_targets_copilot(config)
        }
        [interpreter, flag, script] if flag == "-I" => bridge.is_some_and(|(current, bridge)| {
            same_path(interpreter, current) && same_path(script, bridge)
        }),
        [executable, rest @ ..] if rest.len() >= 2 => inline_targets_copilot(executable, rest),
        _ => false,
    }
}

/// A `python [flags] -c <code> [config]` bridge whose Guard argv targets the
/// Copilot harness.
fn inline_targets_copilot(executable: &str, rest: &[String]) -> bool {
    if !file_name(executable).to_lowercase().starts_with("python") {
        return false;
    }
    let Some(code_flag) = rest.iter().position(|token| token == "-c") else {
        return false;
    };
    if !rest[..code_flag]
        .iter()
        .all(|flag| INTERPRETER_FLAGS.contains(&flag.as_str()))
    {
        return false;
    }
    let Some(code) = rest.get(code_flag + 1) else {
        return false;
    };
    if code.contains("bounded_cli_hook_bridge") && rest.len() == code_flag + 3 {
        return config_targets_copilot(&rest[code_flag + 2]);
    }
    code.contains("codex_plugin_scanner.cli")
        && inline_guard_args(code).is_some_and(|argv| argv_targets_copilot(&argv))
}

/// A bridge config naming the Copilot harness with a Guard hook argv.
fn config_targets_copilot(config: &str) -> bool {
    let Ok(OValue::Map(config)) = parse_python_json(config) else {
        return false;
    };
    config.get_str("harness") == Some("copilot")
        && config
            .get("cli_args")
            .and_then(|args| lowered_strings(Some(args)))
            .is_some_and(|argv| argv_targets_copilot(&argv))
}

/// The argv an inline bridge passes to `json.loads('<literal>')`.
fn inline_guard_args(code: &str) -> Option<Vec<String>> {
    let literal = INLINE_ARGS.captures(code)?.get(1)?.as_str();
    let payload = py_string_literal(literal)?;
    lowered_strings(parse_python_json(&payload).ok().as_ref())
}

/// Every item lowercased, or `None` unless the value is a list of strings.
fn lowered_strings(value: Option<&OValue>) -> Option<Vec<String>> {
    value?
        .as_list()?
        .iter()
        .map(|item| item.as_str().map(str::to_lowercase))
        .collect()
}

/// The first `--harness` decides: it must name Copilot, and the argv must
/// carry `guard` and `hook`.
fn argv_targets_copilot(argv: &[String]) -> bool {
    let carries_hook =
        || argv.iter().any(|token| token == "guard") && argv.iter().any(|token| token == "hook");
    for (index, token) in argv.iter().enumerate() {
        if token == "--harness" && argv.get(index + 1).is_some_and(|next| next == "copilot") {
            return carries_hook();
        }
        if token.strip_prefix("--harness=") == Some("copilot") {
            return carries_hook();
        }
    }
    false
}

/// `Path(text).name`.
fn file_name(text: &str) -> String {
    Path::new(text)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `Path(left).resolve() == Path(right).resolve()`.
fn same_path(left: &str, right: &str) -> bool {
    resolve_lenient(Path::new(left)) == resolve_lenient(Path::new(right))
}

/// `ast.literal_eval` of one quoted, unprefixed string literal; `None` for
/// anything Python would refuse.
fn py_string_literal(literal: &str) -> Option<String> {
    let quote = literal.chars().next()?;
    let body = literal.strip_prefix(quote)?.strip_suffix(quote)?;
    let mut chars = body.chars().peekable();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch == '\n' || ch == '\r' {
            return None;
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let escape = chars.next()?;
        match escape {
            '\\' | '\'' | '"' => out.push(escape),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '0'..='7' => {
                let mut value = escape.to_digit(8)?;
                for _ in 0..2 {
                    match chars.peek().and_then(|next| next.to_digit(8)) {
                        Some(digit) => {
                            value = value * 8 + digit;
                            chars.next();
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(value)?);
            }
            'x' => out.push(hex_escape(&mut chars, 2)?),
            'u' => out.push(hex_escape(&mut chars, 4)?),
            'U' => out.push(hex_escape(&mut chars, 8)?),
            'N' => return None,
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

/// A fixed-width hex escape; a lone surrogate, which Rust strings cannot
/// hold, reads as U+FFFD.
fn hex_escape(chars: &mut impl Iterator<Item = char>, width: usize) -> Option<char> {
    let digits: String = chars.take(width).collect();
    if digits.chars().count() != width || !digits.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(&digits, 16).ok()?;
    if (0xD800..0xE000).contains(&value) {
        return Some('\u{FFFD}');
    }
    char::from_u32(value)
}

#[cfg(test)]
#[path = "copilot_hook_commands_tests.rs"]
mod tests;
