//! `runner_authority` kind `pi_extension_render`: the Pi and Oh My Pi Guard
//! extension source. The template in `pi_extension_render.v1.json` was
//! recorded from the original Python builders, so the rendered source matches
//! them byte for byte. Python resolves runtime ownership, the taskkill path
//! and the compatibility version; this kind only renders.
//!
//! Template lines carry `@@name@@` placeholders. `@@if omp@@`/`@@if pi@@` and
//! `@@fi@@` lines bracket harness-only blocks, and `@@begin name@@`/`@@end
//! name@@` lines mark fragments tests read back; both marker kinds are dropped
//! from the output. A placeholder value is never rescanned.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use guard_contracts::write_python_default_json;
use serde_json::{json, Map, Value};

use super::runner_authority_op::{KindResult, ERR_INVALID};

const TEMPLATE: &str = include_str!("pi_extension_render.v1.json");
const TEMPLATE_SCHEMA: &str = "guard-pi-extension-render-template.v1";
const ERR_TEMPLATE: &str = "pi_extension_render_template_invalid";

/// The fields both variants take, and the ones only the active one adds.
const COMMON_FIELDS: [&str; 16] = [
    "variant",
    "harness",
    "display_name",
    "guard_args",
    "guard_home",
    "home_dir",
    "home_dir_is_default",
    "config_path",
    "compatibility_version",
    "cli_command",
    "cli_args",
    "cli_accepts_json_args",
    "recovery_command",
    "recovery_args",
    "recovery_accepts_failure_kind",
    "taskkill_path",
];
const ACTIVE_FIELDS: [&str; 3] = [
    "native_hook_runtime",
    "contained_sink_command",
    "contained_request_root",
];

struct Template {
    active: Vec<String>,
    previous: Vec<String>,
}

fn template() -> Result<&'static Template, &'static str> {
    static PARSED: OnceLock<Option<Template>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            let document: Value = serde_json::from_str(TEMPLATE).ok()?;
            if document.get("schema").and_then(Value::as_str) != Some(TEMPLATE_SCHEMA) {
                return None;
            }
            let variants = document.get("variants")?;
            let lines = |name: &str| -> Option<Vec<String>> {
                variants
                    .get(name)?
                    .as_array()?
                    .iter()
                    .map(|line| line.as_str().map(str::to_owned))
                    .collect()
            };
            Some(Template {
                active: lines("active")?,
                previous: lines("previous")?,
            })
        })
        .as_ref()
        .ok_or(ERR_TEMPLATE)
}

fn json_text(value: &Value) -> Result<String, &'static str> {
    let mut out = Vec::new();
    write_python_default_json(value, &mut out).map_err(|_| ERR_INVALID)?;
    String::from_utf8(out).map_err(|_| ERR_INVALID)
}

fn string<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a Value, &'static str> {
    fields
        .get(key)
        .filter(|value| value.is_string())
        .ok_or(ERR_INVALID)
}

fn optional_string<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, &'static str> {
    fields
        .get(key)
        .filter(|value| value.is_string() || value.is_null())
        .ok_or(ERR_INVALID)
}

fn strings<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a Value, &'static str> {
    fields
        .get(key)
        .filter(|value| {
            value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        })
        .ok_or(ERR_INVALID)
}

fn flag(fields: &Map<String, Value>, key: &str) -> Result<&'static str, &'static str> {
    match fields.get(key).and_then(Value::as_bool) {
        Some(true) => Ok("true"),
        Some(false) => Ok("false"),
        None => Err(ERR_INVALID),
    }
}

fn display_name_fragment(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\'' => escaped.push_str("\\'"),
            '"' => escaped.push_str("\\\""),
            '`' => escaped.push_str("\\`"),
            '$' if chars.peek() == Some(&'{') => escaped.push_str("\\$"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

/// The text each placeholder becomes: JSON with Python's default spelling,
/// `true`/`false` for flags, and the display name as written.
fn placeholder_values(
    fields: &Map<String, Value>,
    active: bool,
) -> Result<BTreeMap<&'static str, String>, &'static str> {
    let version = fields
        .get("compatibility_version")
        .filter(|value| value.is_i64() || value.is_u64())
        .ok_or(ERR_INVALID)?;
    let display_name = fields
        .get("display_name")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let mut values = BTreeMap::from([
        ("display_name", display_name_fragment(display_name)),
        ("guard_args", json_text(strings(fields, "guard_args")?)?),
        ("guard_home", json_text(string(fields, "guard_home")?)?),
        ("home_dir", json_text(string(fields, "home_dir")?)?),
        (
            "home_dir_is_default",
            flag(fields, "home_dir_is_default")?.to_owned(),
        ),
        ("config_path", json_text(string(fields, "config_path")?)?),
        ("compatibility_version", json_text(version)?),
        ("cli_command", json_text(string(fields, "cli_command")?)?),
        ("cli_args", json_text(strings(fields, "cli_args")?)?),
        (
            "cli_accepts_json_args",
            flag(fields, "cli_accepts_json_args")?.to_owned(),
        ),
        (
            "recovery_command",
            json_text(string(fields, "recovery_command")?)?,
        ),
        (
            "recovery_args",
            json_text(strings(fields, "recovery_args")?)?,
        ),
        (
            "recovery_accepts_failure_kind",
            flag(fields, "recovery_accepts_failure_kind")?.to_owned(),
        ),
        (
            "taskkill_path",
            json_text(optional_string(fields, "taskkill_path")?)?,
        ),
    ]);
    if active {
        values.insert(
            "native_hook_runtime",
            json_text(optional_string(fields, "native_hook_runtime")?)?,
        );
        values.insert(
            "contained_sink_command",
            json_text(strings(fields, "contained_sink_command")?)?,
        );
        values.insert(
            "contained_request_root",
            json_text(string(fields, "contained_request_root")?)?,
        );
    }
    Ok(values)
}

/// One template line with each `@@name@@` replaced in a single pass.
fn substitute(
    line: &str,
    values: &BTreeMap<&'static str, String>,
    out: &mut String,
) -> Result<(), &'static str> {
    let mut parts = line.split("@@");
    out.push_str(parts.next().unwrap_or_default());
    while let Some(name) = parts.next() {
        out.push_str(values.get(name).ok_or(ERR_TEMPLATE)?);
        out.push_str(parts.next().ok_or(ERR_TEMPLATE)?);
    }
    Ok(())
}

fn marker<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix)?.strip_suffix("@@")
}

fn render_lines(
    lines: &[String],
    harness: &str,
    values: &BTreeMap<&'static str, String>,
) -> Result<String, &'static str> {
    let mut source = String::with_capacity(lines.iter().map(|line| line.len() + 1).sum());
    let mut selected: Option<&str> = None;
    let mut first = true;
    for line in lines {
        if let Some(name) = marker(line, "@@if ") {
            if selected.replace(name).is_some() {
                return Err(ERR_TEMPLATE);
            }
            continue;
        }
        if line == "@@fi@@" {
            selected.take().ok_or(ERR_TEMPLATE)?;
            continue;
        }
        if marker(line, "@@begin ").is_some() || marker(line, "@@end ").is_some() {
            continue;
        }
        if selected.is_some_and(|name| name != harness) {
            continue;
        }
        if !first {
            source.push('\n');
        }
        first = false;
        substitute(line, values, &mut source)?;
    }
    if selected.is_some() {
        return Err(ERR_TEMPLATE);
    }
    Ok(source)
}

/// The extension source for `variant` (`active` or `previous`) and `harness`
/// (`omp` or `pi`), as `{"source": <text>}`.
pub(crate) fn render(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    let active = match fields.get("variant").and_then(Value::as_str) {
        Some("active") => true,
        Some("previous") => false,
        _ => return Err(ERR_INVALID),
    };
    let harness = fields
        .get("harness")
        .and_then(Value::as_str)
        .filter(|harness| matches!(*harness, "omp" | "pi"))
        .ok_or(ERR_INVALID)?;
    let expected = COMMON_FIELDS.len() + if active { ACTIVE_FIELDS.len() } else { 0 };
    let known = |key: &String| {
        COMMON_FIELDS.contains(&key.as_str()) || (active && ACTIVE_FIELDS.contains(&key.as_str()))
    };
    if fields.len() != expected || !fields.keys().all(known) {
        return Err(ERR_INVALID);
    }
    let values = placeholder_values(fields, active)?;
    let template = template()?;
    let lines = if active {
        &template.active
    } else {
        &template.previous
    };
    Ok(json!({"source": render_lines(lines, harness, &values)?}))
}
