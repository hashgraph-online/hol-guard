//! CPython text rules the native Claude hook bridge's HTTP client keeps:
//! `str.isspace`, `int()` on a status code, Latin-1 header decoding and
//! `http.client`'s request-target validation.

use crate::claude_hook_bridge_transport::{escape_code_point, py_repr, BridgeError};

/// CPython `str.isspace()` over the Latin-1 range a status line decodes to.
pub(crate) fn py_isspace(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// CPython `int(text)` for a base-10 literal: surrounding whitespace, an
/// optional sign and single underscores between digits.
pub(crate) fn py_int(text: &str) -> Option<i128> {
    let text = text.trim_matches(py_isspace);
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return None;
    }
    if digits.contains("__") || !digits.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    let value: i128 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -value } else { value })
}

pub(crate) fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// `http.client`'s `_validate_path` and the ASCII encoding of the request
/// line, with the `ValueError` text each raises.
pub(crate) fn validate_request_target(url: &str) -> Result<(), BridgeError> {
    if let Some(found) = url
        .chars()
        .find(|c| matches!(*c, '\u{0}'..='\u{20}' | '\u{7f}'))
    {
        return Err(BridgeError::Value(format!(
            "URL can't contain control characters. {} (found at least {})",
            py_repr(url),
            py_repr(&found.to_string())
        )));
    }
    let line: Vec<char> = format!("POST {url} HTTP/1.1").chars().collect();
    let Some(start) = line.iter().position(|c| !c.is_ascii()) else {
        return Ok(());
    };
    let end = line[start..]
        .iter()
        .position(char::is_ascii)
        .map_or(line.len(), |offset| start + offset);
    let detail = if end - start == 1 {
        format!(
            "character '{}' in position {start}",
            escape_code_point(line[start])
        )
    } else {
        format!("characters in position {start}-{}", end - 1)
    };
    Err(BridgeError::Value(format!(
        "'ascii' codec can't encode {detail}: ordinal not in range(128)"
    )))
}
