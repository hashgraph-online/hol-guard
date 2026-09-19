//! Ordered, bounded output extraction shared by inline review and output hashes.

use crate::ExtractedOutput;
use guard_rules::{
    MAX_CONTENT_ITEMS, MAX_DEPTH, MAX_OBJECT_KEYS, MAX_OUTPUT_CHARS, OUTPUT_TEXT_KEYS,
    PAYLOAD_OUTPUT_KEYS,
};
use serde_json::Value;
use std::collections::HashSet;

fn append_bounded(text: &str, output: &mut String, chars: &mut usize) -> bool {
    let remaining = MAX_OUTPUT_CHARS.saturating_sub(*chars);
    let text_chars = text.chars().count();
    if text_chars > remaining {
        let end = text
            .char_indices()
            .nth(remaining)
            .map_or(text.len(), |(index, _)| index);
        output.push_str(&text[..end]);
        *chars = MAX_OUTPUT_CHARS;
        true
    } else {
        output.push_str(text);
        *chars += text_chars;
        false
    }
}

fn collect_output_text(value: &Value) -> ExtractedOutput {
    fn append(output: &mut String, chars: &mut usize, truncated: &mut bool, text: &str) {
        if *truncated || text.is_empty() {
            return;
        }
        *truncated = append_bounded(text, output, chars);
    }

    fn traverse(
        value: &Value,
        depth: usize,
        output: &mut String,
        chars: &mut usize,
        truncated: &mut bool,
        seen: &mut HashSet<usize>,
    ) {
        if *truncated {
            return;
        }
        if depth > MAX_DEPTH {
            *truncated = true;
            return;
        }
        match value {
            Value::String(text) => append(output, chars, truncated, text),
            Value::Array(items) => {
                let id = value as *const Value as usize;
                if !seen.insert(id) {
                    *truncated = true;
                    return;
                }
                for item in items.iter().take(MAX_CONTENT_ITEMS) {
                    traverse(item, depth + 1, output, chars, truncated, seen);
                    if *truncated {
                        break;
                    }
                }
                if items.len() > MAX_CONTENT_ITEMS {
                    *truncated = true;
                }
                seen.remove(&id);
            }
            Value::Object(record) => {
                if record.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = record.get("text").and_then(Value::as_str) {
                        append(output, chars, truncated, text);
                        return;
                    }
                }
                let id = value as *const Value as usize;
                if !seen.insert(id) {
                    *truncated = true;
                    return;
                }
                let mut keys_seen = 0usize;
                for key in OUTPUT_TEXT_KEYS {
                    let Some(child) = record.get(*key) else {
                        continue;
                    };
                    if keys_seen >= MAX_OBJECT_KEYS {
                        *truncated = true;
                        break;
                    }
                    keys_seen += 1;
                    traverse(child, depth + 1, output, chars, truncated, seen);
                    if *truncated {
                        break;
                    }
                }
                seen.remove(&id);
            }
            _ => {}
        }
    }

    let mut text = String::new();
    let mut chars = 0usize;
    let mut truncated = false;
    let mut seen = HashSet::new();
    traverse(value, 0, &mut text, &mut chars, &mut truncated, &mut seen);
    ExtractedOutput {
        text,
        chars,
        truncated,
    }
}

pub fn extract_payload_output(payload: &Value) -> ExtractedOutput {
    let Some(record) = payload.as_object() else {
        return ExtractedOutput {
            text: String::new(),
            chars: 0,
            truncated: false,
        };
    };
    let mut text = String::new();
    let mut chars = 0usize;
    let mut truncated = false;
    for key in PAYLOAD_OUTPUT_KEYS {
        if let Some(value) = record.get(*key) {
            let result = collect_output_text(value);
            truncated |= result.truncated;
            if !result.text.is_empty() {
                if !text.is_empty() {
                    truncated |= append_bounded("\n", &mut text, &mut chars);
                }
                truncated |= append_bounded(&result.text, &mut text, &mut chars);
            }
        }
    }
    ExtractedOutput {
        text,
        chars,
        truncated,
    }
}
