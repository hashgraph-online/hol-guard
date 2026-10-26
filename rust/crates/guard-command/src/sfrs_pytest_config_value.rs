//! Raw pytest config values and the option text derived from them
//! (`pytest_config._config_value` and its helpers).
//!
//! Only the emptiness of the `log_file`, `pythonpath` and `required_plugins`
//! texts reaches a decision; the other option texts are kept for the evidence
//! record. Table values nested in an INI-compatible `ini_options` entry are
//! rendered as compact JSON instead of the Python `dict` repr: both are never
//! empty, which is the only property the classifier reads.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::codex_output_py::py_strip;
use crate::sfrs_shlex::{split_with, COMMENT_LEXER};

pub(crate) const UNSAFE_ADDOPTS_MARKERS: &[&str] = &[
    "--basetemp",
    "--cache-clear",
    "--config-file",
    "--debug",
    "--junit-xml",
    "--junitxml",
    "--log-file",
    "--confcutdir",
    "--override-ini",
    "--rootdir",
    "-c",
    "-o",
];
const UNSAFE_VALUE_KEYS: &[&str] = &["log_file", "pythonpath", "required_plugins"];

/// `PytestConfigValue`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct PytestConfigValue {
    pub(crate) addopts: Vec<String>,
    pub(crate) log_file: Option<String>,
    pub(crate) execution_options: Vec<(String, String)>,
    pub(crate) unsafe_options: bool,
}

/// One parsed config value, as `tomllib` or `configparser` produced it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Raw {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    /// `str(value)` of a date, time or datetime.
    Date(String),
    List(Vec<Raw>),
    Table(BTreeMap<String, Raw>),
}

/// The exception class a failed value raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueFailure {
    /// `ValueError`.
    Value,
    /// `TypeError`.
    Type,
}

/// `_config_value`.
pub(crate) fn config_value(
    options: &BTreeMap<String, Raw>,
) -> Result<PytestConfigValue, ValueFailure> {
    let addopts = addopts_tokens(options.get("addopts"))?;
    let log_file = optional_config_string(options.get("log_file"))?;
    let mut execution_options = Vec::new();
    for (key, raw) in options {
        if key == "addopts" {
            execution_options.push((key.clone(), addopts.join(" ")));
        } else {
            execution_options.push((key.clone(), execution_option_text(raw)));
        }
    }
    let unsafe_options = addopts_are_unsafe(&addopts)
        || execution_options.iter().any(|(key, value)| {
            UNSAFE_VALUE_KEYS.contains(&key.as_str()) && !py_strip(value).is_empty()
        });
    Ok(PytestConfigValue {
        addopts,
        log_file,
        execution_options,
        unsafe_options,
    })
}

/// `_execution_option_text`.
pub(crate) fn execution_option_text(value: &Raw) -> String {
    match value {
        Raw::Str(text) => text.clone(),
        Raw::List(items) => items
            .iter()
            .map(execution_option_text)
            .collect::<Vec<_>>()
            .join("\n"),
        Raw::Table(_) => json_compact(value),
        Raw::Bool(_) | Raw::Int(_) | Raw::Float(_) => json_compact(value),
        Raw::Date(text) => text.clone(),
    }
}

/// `_addopts_tokens`.
pub(crate) fn addopts_tokens(value: Option<&Raw>) -> Result<Vec<String>, ValueFailure> {
    match value {
        None => Ok(Vec::new()),
        Some(Raw::List(items)) => items
            .iter()
            .map(|item| match item {
                Raw::Str(text) => Ok(text.clone()),
                _ => Err(ValueFailure::Type),
            })
            .collect(),
        Some(Raw::Str(text)) => split_with(COMMENT_LEXER, text).map_err(|_| ValueFailure::Value),
        Some(_) => Err(ValueFailure::Type),
    }
}

/// `_optional_config_string`.
pub(crate) fn optional_config_string(value: Option<&Raw>) -> Result<Option<String>, ValueFailure> {
    match value {
        None => Ok(None),
        Some(Raw::Str(text)) => {
            let stripped = py_strip(text);
            Ok((!stripped.is_empty()).then(|| stripped.to_owned()))
        }
        Some(_) => Err(ValueFailure::Type),
    }
}

/// `_addopts_are_unsafe`.
pub(crate) fn addopts_are_unsafe(tokens: &[String]) -> bool {
    for token in tokens {
        if token == "-p" || (token.starts_with("-p") && !token.starts_with("--")) {
            return true;
        }
        if UNSAFE_ADDOPTS_MARKERS.contains(&token.as_str()) {
            return true;
        }
        if UNSAFE_ADDOPTS_MARKERS
            .iter()
            .filter(|marker| **marker != "-c")
            .any(|marker| {
                token
                    .strip_prefix(marker)
                    .is_some_and(|rest| rest.starts_with('='))
            })
        {
            return true;
        }
        if (token.starts_with("-c") && token != "-c") || (token.starts_with("-o") && token != "-o")
        {
            return true;
        }
    }
    false
}

/// `str(value)` for a scalar or table kept by the INI-compatible conversion.
pub(crate) fn py_str(value: &Raw) -> String {
    match value {
        Raw::Str(text) | Raw::Date(text) => text.clone(),
        Raw::Bool(true) => "True".to_owned(),
        Raw::Bool(false) => "False".to_owned(),
        Raw::Int(number) => number.to_string(),
        Raw::Float(number) => float_str(*number),
        Raw::List(_) | Raw::Table(_) => json_compact(value),
    }
}

fn float_str(number: f64) -> String {
    if number.is_nan() {
        "nan".to_owned()
    } else if number.is_infinite() {
        if number > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        float_repr(number)
    }
}

/// `repr(float)` for a finite number.
pub(crate) fn float_repr(number: f64) -> String {
    let scientific = format!("{number:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("exponent");
    let exponent: i32 = exponent.parse().expect("exponent digits");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let count = digits.len();
    let sign = if negative { "-" } else { "" };
    let body = if (0..16).contains(&exponent) {
        let point = exponent as usize + 1;
        if count <= point {
            format!("{digits}{}.0", "0".repeat(point - count))
        } else {
            format!("{}.{}", &digits[..point], &digits[point..])
        }
    } else if (-4..0).contains(&exponent) {
        format!("0.{}{digits}", "0".repeat((-exponent - 1) as usize))
    } else {
        let tail = if count > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        format!(
            "{}{tail}e{exponent_sign}{:02}",
            &digits[..1],
            exponent.abs()
        )
    };
    format!("{sign}{body}")
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)`.
pub(crate) fn json_compact(value: &Raw) -> String {
    match value {
        Raw::Str(text) | Raw::Date(text) => json_string(text),
        Raw::Bool(true) => "true".to_owned(),
        Raw::Bool(false) => "false".to_owned(),
        Raw::Int(number) => number.to_string(),
        Raw::Float(number) => {
            if number.is_nan() {
                "NaN".to_owned()
            } else if number.is_infinite() {
                if *number > 0.0 {
                    "Infinity"
                } else {
                    "-Infinity"
                }
                .to_owned()
            } else {
                float_repr(*number)
            }
        }
        Raw::List(items) => {
            let inner: Vec<String> = items.iter().map(json_compact).collect();
            format!("[{}]", inner.join(","))
        }
        Raw::Table(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{}:{}", json_string(key), json_compact(item)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// A JSON string literal with `ensure_ascii=True`.
pub(crate) fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            other => {
                let mut units = [0u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::{addopts_are_unsafe, float_repr, json_string};

    #[test]
    fn float_repr_matches_cpython_rules() {
        assert_eq!(float_repr(1.5), "1.5");
        assert_eq!(float_repr(100.0), "100.0");
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1.5e-7), "1.5e-07");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(-0.0), "-0.0");
    }

    #[test]
    fn json_strings_are_ascii() {
        assert_eq!(
            json_string("a\u{e9}\u{1f600}\u{7f}"),
            "\"a\\u00e9\\ud83d\\ude00\\u007f\""
        );
    }

    #[test]
    fn unsafe_addopts_markers() {
        let owned = |text: &str| vec![text.to_owned()];
        assert!(addopts_are_unsafe(&owned("-pfoo")));
        assert!(addopts_are_unsafe(&owned("--rootdir=x")));
        assert!(addopts_are_unsafe(&owned("-ofoo=1")));
        assert!(!addopts_are_unsafe(&owned("--maxfail=1")));
        assert!(addopts_are_unsafe(&owned("-c=x")));
    }
}
