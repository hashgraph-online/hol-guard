//! Cloud-safe text kinds shared by review events and receipt sync:
//! `receipt_sync_privacy.py` and `review_event_display.py`, plus the batched
//! `_cloud_scrub_text` entry point. Pure; no IO.

use guard_command::cloud_scrub::{cloud_scrub_text, redact_sensitive_text};
use serde_json::{json, Map, Value};

use super::cloud_request_payload::{cloud_safe_local_request_payload, local_request_command_text};
use super::cloud_request_text::{py_isspace, py_strip, py_truthy};
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const COMMAND_MAX_UTF16_UNITS: usize = 65_536;
const SUMMARY_MAX_UTF16_UNITS: usize = 512;
const TRUNCATION_MARKER: &str = " \u{2026} [truncated] \u{2026} ";
const RECEIPT_COMMAND_KEYS: [&str; 2] = ["command", "redacted_command"];
const SOURCE_EXCERPT_TOKENS: [&str; 9] = [
    "function ",
    "def ",
    "class ",
    "import ",
    "from ",
    " => ",
    "console.log(",
    "<script",
    "#!/bin/",
];

fn string_array(args: &Map<String, Value>, key: &str) -> Result<Vec<String>, &'static str> {
    args.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

/// Kind `cloud_scrub_texts`: `_cloud_scrub_text` over a batch.
pub(crate) fn cloud_scrub_texts(args: &Value) -> KindResult {
    let texts = string_array(args_object(args)?, "texts")?;
    let scrubbed: Vec<String> = texts.iter().map(|text| cloud_scrub_text(text)).collect();
    Ok(json!({ "texts": scrubbed }))
}

fn looks_like_source_excerpt(value: &str) -> bool {
    let lowered = value.to_lowercase();
    let structured = value.contains('\n') && value.contains(['{', '}', ';']);
    structured
        || SOURCE_EXCERPT_TOKENS
            .iter()
            .any(|token| lowered.contains(token))
}

/// `cloud_sync_sanitize_text`.
pub(crate) fn sanitize_text(value: &str, fallback: &str) -> String {
    let redacted = redact_sensitive_text(value);
    let stripped = py_strip(&redacted);
    if stripped.is_empty() || looks_like_source_excerpt(stripped) {
        return fallback.to_owned();
    }
    if stripped.chars().count() > 320 {
        let prefix: String = stripped.chars().take(317).collect();
        return format!("{prefix}...");
    }
    stripped.to_owned()
}

/// `cloud_sync_command_display_part`.
pub(crate) fn command_display_part(value: &str) -> String {
    let sanitized = sanitize_text(&cloud_scrub_text(value), "");
    sanitized
        .split(py_isspace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `cloud_sync_scrub_envelope_commands`.
pub(crate) fn scrub_envelope_commands(
    envelope: &Map<String, Value>,
    level: &str,
) -> Map<String, Value> {
    let mut safe = envelope.clone();
    for key in RECEIPT_COMMAND_KEYS {
        let Some(Value::String(value)) = safe.get(key) else {
            continue;
        };
        if level == "full" {
            safe.remove(key);
        } else {
            let display = command_display_part(value);
            safe.insert(key.to_owned(), Value::String(display));
        }
    }
    safe
}

fn utf16_units(value: &str) -> usize {
    value
        .chars()
        .map(|c| if (c as u32) > 0xFFFF { 2 } else { 1 })
        .sum()
}

fn utf16_prefix(value: &str, max_units: usize) -> String {
    let mut units = 0;
    let mut end = value.len();
    for (index, character) in value.char_indices() {
        units += if (character as u32) > 0xFFFF { 2 } else { 1 };
        if units > max_units {
            end = index;
            break;
        }
    }
    value[..end].to_owned()
}

fn utf16_suffix(value: &str, max_units: usize) -> String {
    let mut units = 0;
    let mut start = 0;
    for (index, character) in value.char_indices().rev() {
        units += if (character as u32) > 0xFFFF { 2 } else { 1 };
        if units > max_units {
            start = index + character.len_utf8();
            break;
        }
    }
    value[start..].to_owned()
}

fn truncate_utf16(value: &str, max_units: usize) -> String {
    if utf16_units(value) <= max_units {
        return value.to_owned();
    }
    let available = max_units.saturating_sub(utf16_units(TRUNCATION_MARKER));
    let prefix_units = available * 3 / 4;
    let suffix_units = available - prefix_units;
    format!(
        "{}{}{}",
        utf16_prefix(value, prefix_units),
        TRUNCATION_MARKER,
        utf16_suffix(value, suffix_units)
    )
}

fn text_field(
    item: &Map<String, Value>,
    keys: &[&str],
    fallback: &str,
) -> Result<String, &'static str> {
    for key in keys {
        if let Some(value) = item.get(*key).filter(|value| py_truthy(value)) {
            return match value {
                Value::String(text) => Ok(text.clone()),
                Value::Number(number) => Ok(number.to_string()),
                Value::Bool(true) => Ok("True".to_owned()),
                _ => Err(ERR_INVALID),
            };
        }
    }
    Ok(fallback.to_owned())
}

/// Display command, summary, raw command and redacted command.
type DisplayFields = (String, String, Option<String>, Option<String>);

/// `build_display_command`.
fn display_command(item: &Map<String, Value>, level: &str) -> Result<DisplayFields, &'static str> {
    let identity = text_field(item, &["action_identity", "artifact_id"], "unknown")?;
    let trigger = text_field(
        item,
        &["trigger_summary", "why_now"],
        "Guard approval request",
    )?;
    let headline = text_field(item, &["risk_headline", "risk_summary"], "")?;
    let harness = text_field(item, &["harness"], "guard-review")?;
    let fallback = format!(
        "{}: {}",
        cloud_scrub_text(&harness),
        cloud_scrub_text(&identity)
    );
    let envelope = item.get("action_envelope_json").and_then(Value::as_object);
    let safe_command = local_request_command_text(item, envelope)
        .map(|text| cloud_scrub_text(&text))
        .filter(|text| !text.is_empty());
    let command_source = safe_command.clone().unwrap_or(fallback);
    let command = truncate_utf16(&command_source, COMMAND_MAX_UTF16_UNITS);
    let summary = if headline.is_empty() {
        trigger
    } else {
        format!("{headline} \u{2014} {trigger}")
    };
    let summary = truncate_utf16(&summary, SUMMARY_MAX_UTF16_UNITS);
    let has_command = safe_command.is_some();
    let raw = (level == "none" && has_command).then(|| command.clone());
    let redacted = (level != "none" && has_command).then(|| command.clone());
    Ok((command, summary, raw, redacted))
}

fn display_provenance(has_command_details: bool, level: &str) -> &'static str {
    if level == "none" {
        "raw"
    } else if level == "full" && !has_command_details {
        "withheld"
    } else {
        "redacted"
    }
}

/// Kind `cloud_review_event_display`: the display fields and the Cloud-safe
/// request payload of one review event, in one round trip.
pub(crate) fn cloud_review_event_display(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let item = args_object(args.get("item").ok_or(ERR_INVALID)?)?;
    let level = args
        .get("redaction_level")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let (command, summary, raw, redacted) = display_command(item, level)?;
    let payload = cloud_safe_local_request_payload(item, level, None)?;
    let has_command = payload.get("command_text").is_some_and(py_truthy);
    Ok(json!({
        "display_command": command,
        "display_summary": summary,
        "raw_command": raw,
        "redacted_command": redacted,
        "display_provenance": display_provenance(has_command, level),
        "payload": payload,
    }))
}
