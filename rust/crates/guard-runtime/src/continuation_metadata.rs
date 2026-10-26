//! Compatibility codec for passive legacy metadata, including nonfinite floats.
use crate::guard_store_db::{StoreError, StoreResult};
use serde_json::Value;

pub(crate) fn legacy_value(text: &str) -> Value {
    let bytes = text.as_bytes();
    let mut normalized = Vec::with_capacity(bytes.len());
    let (mut position, mut quoted, mut escaped) = (0, false, false);
    while position < bytes.len() {
        let byte = bytes[position];
        if quoted {
            normalized.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            position += 1;
            continue;
        }
        if byte == b'"' {
            quoted = true;
        }
        let token = [
            b"-Infinity".as_slice(),
            b"Infinity".as_slice(),
            b"NaN".as_slice(),
        ]
        .into_iter()
        .find(|token| {
            bytes[position..].starts_with(token)
                && bytes
                    .get(position + token.len())
                    .is_none_or(|b| b.is_ascii_whitespace() || matches!(*b, b',' | b']' | b'}'))
        });
        if let Some(token) = token {
            normalized.extend_from_slice(b"null");
            position += token.len();
        } else {
            normalized.push(byte);
            position += 1;
        }
    }
    serde_json::from_slice(&normalized).unwrap_or(Value::Null)
}

fn at_path<'a>(mut value: &'a mut Value, path: &[Value]) -> Option<&'a mut Value> {
    for part in path {
        value = if let Some(key) = part.as_str() {
            value.get_mut(key)?
        } else {
            value.get_mut(usize::try_from(part.as_u64()?).ok()?)?
        };
    }
    Some(value)
}

/// An ASCII JSON string literal, as `json.dumps` writes a string holding a
/// lone surrogate that the UTF-8 request envelope cannot carry.
fn is_escaped_string(text: &str) -> bool {
    text.is_ascii()
        && text.starts_with('"')
        && matches!(crate::pyjson::parse(text), Ok(crate::pyjson::PyVal::Str(_)))
}

pub(crate) fn serialize(
    mut metadata: Value,
    nonfinite: &Value,
    retained: bool,
) -> StoreResult<String> {
    let mut text = crate::guard_store_json::dumps_default(&metadata)
        .ok_or(StoreError::Invalid("continuation_metadata_invalid"))?;
    let mut replacements = Vec::new();
    let mut counter = 0;
    for record in nonfinite.as_array().into_iter().flatten() {
        let path = record[0]
            .as_array()
            .ok_or(StoreError::Invalid("continuation_metadata_invalid"))?;
        let token = record[1]
            .as_str()
            .filter(|s| matches!(*s, "NaN" | "Infinity" | "-Infinity") || is_escaped_string(s))
            .ok_or(StoreError::Invalid("continuation_metadata_invalid"))?;
        if retained && path.first().and_then(Value::as_str) == Some("retry_lineage") {
            continue;
        }
        let Some(target) = at_path(&mut metadata, path).filter(|v| v.is_null()) else {
            continue;
        };
        let (marker, encoded) = loop {
            let marker = format!("guard-continuation-nonfinite-{counter}");
            counter += 1;
            let encoded = serde_json::to_string(&marker)
                .map_err(|_| StoreError::Invalid("continuation_metadata_invalid"))?;
            if !text.contains(&encoded) {
                break (marker, encoded);
            }
        };
        *target = Value::String(marker);
        replacements.push((encoded, token));
        text = crate::guard_store_json::dumps_default(&metadata)
            .ok_or(StoreError::Invalid("continuation_metadata_invalid"))?;
    }
    for (marker, token) in replacements {
        text = text.replace(&marker, token);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    #[test]
    fn nonfinite_values_remain_data_and_cannot_replace_retained_lineage() {
        let value = serde_json::json!({"legacy_score":null,"retry_lineage":{"version":1},"real":"guard-continuation-nonfinite-0"});
        let markers =
            serde_json::json!([[["legacy_score"], "NaN"], [["retry_lineage"], "Infinity"]]);
        let text = super::serialize(value, &markers, true).unwrap();
        assert!(text.contains("\"legacy_score\": NaN"));
        assert!(text.contains("\"real\": \"guard-continuation-nonfinite-0\""));
        let decoded = super::legacy_value(&text);
        assert_eq!(decoded["retry_lineage"]["version"], 1);
        assert!(decoded["legacy_score"].is_null());
    }

    #[test]
    fn embedded_marker_text_in_other_strings_is_left_unchanged() {
        let value = serde_json::json!({
            "note": "prefixguard-continuation-nonfinite-0suffix",
            "quoted": "x\"guard-continuation-nonfinite-1",
            "score": null
        });
        let markers = serde_json::json!([[["score"], "NaN"]]);
        let text = super::serialize(value, &markers, false).unwrap();
        assert_eq!(
            text,
            r#"{"note": "prefixguard-continuation-nonfinite-0suffix", "quoted": "x\"guard-continuation-nonfinite-1", "score": NaN}"#
        );
    }

    #[test]
    fn escaped_lone_surrogate_strings_are_restored_verbatim() {
        let value = serde_json::json!({"label": null, "score": null});
        let markers = serde_json::json!([[["label"], "\"a\\ud800b\""], [["score"], "-Infinity"]]);
        let text = super::serialize(value, &markers, false).unwrap();
        assert_eq!(text, r#"{"label": "a\ud800b", "score": -Infinity}"#);
        for invalid in ["\"a\" ,1", "{\"a\": 1}", "\"\u{e9}\"", "1"] {
            let markers = serde_json::json!([[["label"], invalid]]);
            let value = serde_json::json!({"label": null});
            assert!(
                super::serialize(value, &markers, false).is_err(),
                "{invalid}"
            );
        }
    }
}
