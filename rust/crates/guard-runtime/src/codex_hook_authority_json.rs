//! Python `json` compatibility for the signed Codex hook records: the
//! canonical text `json.dumps` signs, and the values `json.loads` accepts.

use serde_json::Value;

/// `json.loads`: also accepts the bare `NaN`, `Infinity` and `-Infinity`
/// literals, reading them as `null`. The flag says one was present: Python
/// refused to re-encode such a record for its signature check, so the
/// caller must refuse to authenticate it rather than check the `null` form.
pub(super) fn parse_python_json(raw: &str) -> Result<(Value, bool), serde_json::Error> {
    match serde_json::from_str(raw) {
        Ok(value) => Ok((value, false)),
        Err(error) => match without_nonfinite(raw) {
            Some(text) => serde_json::from_str(&text).map(|value| (value, true)),
            None => Err(error),
        },
    }
}

fn without_nonfinite(raw: &str) -> Option<String> {
    let mut output = String::with_capacity(raw.len());
    let mut replaced = false;
    let mut in_string = false;
    let mut escaped = false;
    let mut rest = raw;
    while let Some(character) = rest.chars().next() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
        } else if let Some(literal) = ["-Infinity", "Infinity", "NaN"]
            .into_iter()
            .find(|literal| rest.starts_with(literal))
        {
            output.push_str("null");
            rest = &rest[literal.len()..];
            replaced = true;
            continue;
        }
        output.push(character);
        rest = &rest[character.len_utf8()..];
    }
    replaced.then_some(output)
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub(super) fn python_canonical_json(value: &Value) -> Option<String> {
    let mut output = Vec::new();
    guard_contracts::write_canonical_json(value, &mut output).ok()?;
    String::from_utf8(output).ok()
}
