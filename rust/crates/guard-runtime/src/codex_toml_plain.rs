//! The plain Codex `config.toml` renderer `codex_config._emit_table` wrote:
//! byte for byte what Guard writes when no original file can be kept.

use super::super::pyjson::{float_repr, PyVal};
use super::HookVal;

/// The plain renderer: scalars first, then each nested table under its own
/// header, blank lines between.
pub(super) fn render(payload: &[(String, HookVal)]) -> String {
    let mut lines = Vec::new();
    emit_table(&mut lines, &[], payload);
    let rendered = lines.join("\n");
    let rendered = rendered.trim();
    if rendered.is_empty() {
        String::new()
    } else {
        format!("{rendered}\n")
    }
}

fn emit_table(lines: &mut Vec<String>, path: &[&str], payload: &[(String, HookVal)]) {
    let scalars: Vec<&(String, HookVal)> = payload
        .iter()
        .filter(|(_, value)| !matches!(value, HookVal::Null | HookVal::Dict(_)))
        .collect();
    let nested: Vec<(&str, &[(String, HookVal)])> = payload
        .iter()
        .filter_map(|(key, value)| value.as_dict().map(|entries| (key.as_str(), entries)))
        .collect();
    if !path.is_empty() {
        let header: Vec<String> = path.iter().map(|part| format_key(part)).collect();
        lines.push(format!("[{}]", header.join(".")));
    }
    for (key, value) in &scalars {
        lines.push(format!("{} = {}", format_key(key), format_value(value)));
    }
    if !path.is_empty() && (!scalars.is_empty() || !nested.is_empty()) {
        lines.push(String::new());
    }
    for (index, (key, entries)) in nested.iter().enumerate() {
        let mut child = path.to_vec();
        child.push(key);
        emit_table(lines, &child, entries);
        if index + 1 != nested.len() {
            lines.push(String::new());
        }
    }
}

fn format_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if bare {
        key.to_owned()
    } else {
        json_string(key)
    }
}

/// `json.dumps(text)`, ASCII-escaped.
fn json_string(text: &str) -> String {
    let mut out = String::new();
    crate::hook_env_stamp::dumps(&PyVal::Str(text.to_owned()), true, false, &mut out);
    out
}

fn format_value(value: &HookVal) -> String {
    match value {
        HookVal::Bool(flag) => flag.to_string(),
        HookVal::Int(digits) => digits.clone(),
        HookVal::Float(number) => float_repr(*number),
        HookVal::Str(text) => json_string(text),
        HookVal::Dict(entries) if entries.is_empty() => "{}".to_owned(),
        HookVal::Dict(entries) => {
            let items: Vec<String> = entries
                .iter()
                .map(|(key, item)| format!("{} = {}", format_key(key), format_value(item)))
                .collect();
            format!("{{ {} }}", items.join(", "))
        }
        HookVal::List(items) => {
            let items: Vec<String> = items.iter().map(format_value).collect();
            format!("[{}]", items.join(", "))
        }
        // `str(datetime)` puts a space where `isoformat()` puts the `T`.
        HookVal::Temporal("datetime", text) => json_string(&text.replacen('T', " ", 1)),
        HookVal::Temporal(_, text) => json_string(text),
        HookVal::Null => json_string("None"),
    }
}
