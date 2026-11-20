//! Runner-authority kind `kimi_hook_config`: composes the text Guard writes to
//! Kimi Code's `config.toml`. `install` replaces Guard's managed `[[hooks]]`
//! block with one that runs the given hook command; `uninstall` removes it.
//! The edits replay the regular expressions and `str.strip` calls of the
//! original Python byte for byte (see
//! `testdata/kimi/record_kimi_hook_config_vectors.py`).

use regex::Regex;
use serde_json::{json, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const BEGIN: &str = "# BEGIN HOL GUARD MANAGED HOOKS";
const END: &str = "# END HOL GUARD MANAGED HOOKS";
const MARKER: &str = "HOL GUARD MANAGED HOOKS";
const EVENTS: [&str; 5] = [
    "PreToolUse",
    "UserPromptSubmit",
    "PostToolUse",
    "SessionStart",
    "Stop",
];
/// Python's `\s` also matches the ASCII separators U+001C to U+001F.
const SPACE: &str = r"[\s\x1c-\x1f]";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let text = map.get("text").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let cleaned = remove_managed_block(text)?;
    let updated = match map.get("op").and_then(Value::as_str) {
        Some("install") if map.len() == 3 => {
            let command = map
                .get("hook_command")
                .and_then(Value::as_str)
                .ok_or(ERR_INVALID)?;
            let composed = format!(
                "{}\n\n{}\n",
                python_rstrip(&cleaned),
                managed_block(command)
            );
            python_lstrip(&composed).to_string()
        }
        Some("uninstall") if map.len() == 2 => format!("{}\n", python_rstrip(&cleaned)),
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({ "text": updated }))
}

/// Python's `str.isspace`, which adds U+001C to U+001F to Unicode White_Space.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn python_rstrip(text: &str) -> &str {
    text.trim_end_matches(python_space)
}

fn python_lstrip(text: &str) -> &str {
    text.trim_start_matches(python_space)
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn managed_block(command: &str) -> String {
    let escaped = toml_escape(command);
    let mut lines = vec![
        BEGIN.to_string(),
        "# The hooks below are managed by HOL Guard. Do not edit manually.".to_string(),
    ];
    for event in EVENTS {
        lines.push("[[hooks]]".to_string());
        lines.push(format!("event = \"{event}\""));
        lines.push(format!("command = \"{escaped}\""));
        lines.push("timeout = 30".to_string());
    }
    lines.push(END.to_string());
    lines.join("\n")
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
