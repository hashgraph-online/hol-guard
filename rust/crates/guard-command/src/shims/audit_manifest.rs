//! Read a package-shim manifest the way Python `json.loads` accepts an object.
//!
//! `serde_json` rejects `NaN` and `Infinity`. Those tokens stay in the file,
//! and the audit stamp is inserted beside them. Blank text and any other
//! parse failure are returned to the caller so the existing bytes are left
//! untouched.

use serde_json::{Map, Value};

use super::values::py_json_dumps;

#[derive(Debug)]
pub(super) enum ManifestBody {
    Object(Map<String, Value>),
    /// Original object text that contains an unquoted non-finite token.
    NonFinite(String),
}

pub(super) fn read_manifest(text: &str) -> Result<ManifestBody, String> {
    // An existing blank file is not a missing file. A parse error leaves
    // those bytes in place instead of replacing them with a fresh stamp.
    if text.trim().is_empty() {
        return Err("package shim manifest is not strict JSON".to_owned());
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(ManifestBody::Object(map)),
        Ok(_) => Ok(ManifestBody::Object(Map::new())),
        Err(_) if is_nonfinite_object(text) => Ok(ManifestBody::NonFinite(text.to_owned())),
        Err(_) => Err("package shim manifest is not strict JSON".to_owned()),
    }
}

pub(super) fn with_stamp(body: ManifestBody, stamp: &str) -> String {
    match body {
        ManifestBody::Object(mut map) => {
            map.insert("last_audit_at".to_owned(), Value::String(stamp.to_owned()));
            py_json_dumps(&Value::Object(map), true)
        }
        ManifestBody::NonFinite(text) => splice_stamp(&text, stamp),
    }
}

fn is_nonfinite_object(text: &str) -> bool {
    let Some(substituted) = substitute_nonfinite(text) else {
        return false;
    };
    if substituted == text {
        return false;
    }
    matches!(
        serde_json::from_str::<Value>(&substituted),
        Ok(Value::Object(_))
    )
}

fn delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\n' | b'\r' | b':' | b',' | b'[' | b']' | b'{' | b'}'
    )
}

fn substitute_nonfinite(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escape = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            out.push(byte);
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            out.push(byte);
            index += 1;
            continue;
        }
        if let Some(literal) = nonfinite_literal(bytes, index) {
            out.push(b'0');
            index += literal.len();
            continue;
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8(out).ok()
}

fn nonfinite_literal(bytes: &[u8], index: usize) -> Option<&[u8]> {
    let before_ok = index == 0 || delimiter(bytes[index - 1]);
    if !before_ok {
        return None;
    }
    for literal in [
        b"-Infinity".as_slice(),
        b"Infinity".as_slice(),
        b"NaN".as_slice(),
    ] {
        if bytes[index..].starts_with(literal) {
            let after = index + literal.len();
            if after == bytes.len() || delimiter(bytes[after]) {
                return Some(literal);
            }
        }
    }
    None
}

fn splice_stamp(text: &str, stamp: &str) -> String {
    let rendered = serde_json::to_string(stamp).expect("stamp is a string");
    let trimmed = text.trim();
    if let Some(replaced) = replace_top_level_audit_stamps(trimmed, &rendered) {
        return replaced;
    }
    let body = &trimmed[..trimmed.len() - 1];
    let comma = if body.trim_end().ends_with('{') {
        ""
    } else {
        ", "
    };
    format!("{body}{comma}\"last_audit_at\": {rendered}}}")
}

/// Replaces every top-level `last_audit_at` value. Nested keys stay put.
/// `None` means the object has no top-level stamp yet.
fn replace_top_level_audit_stamps(text: &str, rendered: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = skip_ws(bytes, 0);
    if index >= bytes.len() || bytes[index] != b'{' {
        return None;
    }
    index += 1;
    loop {
        index = skip_ws(bytes, index);
        if index >= bytes.len() || bytes[index] == b'}' {
            break;
        }
        if bytes[index] != b'"' {
            return None;
        }
        let key_end = end_of_string(bytes, index);
        let audit_key = bytes[index..key_end] == *b"\"last_audit_at\"";
        index = skip_ws(bytes, key_end);
        if index >= bytes.len() || bytes[index] != b':' {
            return None;
        }
        index = skip_ws(bytes, index + 1);
        let value_end = end_of_value(bytes, index);
        if audit_key {
            spans.push((index, value_end));
        }
        index = skip_ws(bytes, value_end);
        if index < bytes.len() && bytes[index] == b',' {
            index += 1;
            continue;
        }
        break;
    }
    if spans.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end) in spans {
        out.push_str(&text[cursor..start]);
        out.push_str(rendered);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Some(out)
}

fn skip_ws(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\n' | b'\r') {
        index += 1;
    }
    index
}

fn end_of_string(bytes: &[u8], opening: usize) -> usize {
    let mut index = opening + 1;
    let mut escape = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escape {
            escape = false;
        } else if byte == b'\\' {
            escape = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn end_of_value(bytes: &[u8], start: usize) -> usize {
    if start >= bytes.len() {
        return start;
    }
    match bytes[start] {
        b'"' => end_of_string(bytes, start),
        b'{' | b'[' => end_of_container(bytes, start),
        _ => {
            let mut index = start;
            while index < bytes.len()
                && !matches!(
                    bytes[index],
                    b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'
                )
            {
                index += 1;
            }
            index
        }
    }
}

fn end_of_container(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0i32;
    let mut index = start;
    let mut in_string = false;
    let mut escape = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return index;
                }
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::{read_manifest, with_stamp};

    #[test]
    fn blank_or_whitespace_manifest_text_is_not_an_empty_object() {
        for text in ["", " ", "\n\t"] {
            let error = read_manifest(text).expect_err("blank");
            assert!(error.contains("not strict JSON"), "{error}");
        }
    }

    #[test]
    fn a_truncated_nonfinite_object_is_not_treated_as_empty() {
        let error = read_manifest("{\"enabled\": true, \"score\": NaN").expect_err("truncated");
        assert!(error.contains("not strict JSON"), "{error}");
    }

    #[test]
    fn a_second_nonfinite_stamp_replaces_the_top_level_audit_field() {
        let original =
            "{\"enabled\": true, \"score\": NaN, \"nested\": {\"last_audit_at\": \"keep\"}}";
        let once = with_stamp(
            read_manifest(original).expect("read"),
            "2026-01-01T00:00:00+00:00",
        );
        let twice = with_stamp(
            read_manifest(&once).expect("reread"),
            "2026-02-02T00:00:00+00:00",
        );
        assert_eq!(twice.matches("\"last_audit_at\"").count(), 2, "{twice}");
        assert!(
            twice.contains("\"last_audit_at\": \"2026-02-02T00:00:00+00:00\""),
            "{twice}"
        );
        assert!(twice.contains("\"last_audit_at\": \"keep\""), "{twice}");
        assert!(!twice.contains("2026-01-01T00:00:00+00:00"), "{twice}");
        assert!(twice.contains("NaN"), "{twice}");
    }
}
