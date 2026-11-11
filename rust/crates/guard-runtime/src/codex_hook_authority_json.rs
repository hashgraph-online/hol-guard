//! Python `json` compatibility for the signed Codex hook records: the
//! canonical text `json.dumps` signs, and the values `json.loads` accepts.

use serde_json::Value;

/// `json.loads`: also accepts the bare `NaN`, `Infinity` and `-Infinity`
/// literals. They read as `null`, so a record carrying one parses but never
/// authenticates, as it did when Python verified it.
pub(super) fn parse_python_json(raw: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(raw).or_else(|error| match without_nonfinite(raw) {
        Some(text) => serde_json::from_str(&text),
        None => Err(error),
    })
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
    let mut output = String::new();
    write_python_json(value, &mut output)?;
    Some(output)
}

fn write_python_json(value: &Value, output: &mut String) -> Option<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                output.push_str(&number.to_string());
            } else {
                output.push_str(&python_float(number.as_f64()?)?);
            }
        }
        Value::String(text) => write_python_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_python_json(item, output)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            let mut keys: Vec<&String> = object.keys().collect();
            // Python sorts str keys by code point; UTF-8 byte order agrees.
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_python_string(key, output);
                output.push(':');
                write_python_json(&object[key], output)?;
            }
            output.push('}');
        }
    }
    Some(())
}

fn write_python_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            ' '..='~' => output.push(character),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    output.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    output.push('"');
}

/// Python's `repr(float)`: the shortest round-trip digits, in positional
/// form for decimal exponents from -4 through 15 and scientific otherwise.
pub(super) fn python_float(number: f64) -> Option<String> {
    if !number.is_finite() {
        return None;
    }
    let scientific = format!("{number:e}");
    let (mantissa, exponent) = scientific.split_once('e')?;
    let exponent: i32 = exponent.parse().ok()?;
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if negative { "-" } else { "" };
    if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        let body = if point <= 0 {
            format!("0.{}{digits}", "0".repeat(point.unsigned_abs() as usize))
        } else if point as usize >= digits.len() {
            format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
        } else {
            let (whole, fraction) = digits.split_at(point as usize);
            format!("{whole}.{fraction}")
        };
        return Some(format!("{sign}{body}"));
    }
    let (first, rest) = digits.split_at(1);
    let mantissa = if rest.is_empty() {
        first.to_owned()
    } else {
        format!("{first}.{rest}")
    };
    let exponent_sign = if exponent < 0 { '-' } else { '+' };
    Some(format!(
        "{sign}{mantissa}e{exponent_sign}{:02}",
        exponent.unsigned_abs()
    ))
}
