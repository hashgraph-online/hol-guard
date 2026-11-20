//! Scalar text and escapes for the PyYAML emitter in `pyyaml_dump`.

use super::TAG_STR;
use crate::hermes_yaml_resolve::implicit_scalar_tag;
use crate::pyjson::{float_repr, PyVal};

/// The representer's text for a scalar, and whether a plain rendering of it
/// resolves back to the tag it was represented with.
pub(super) fn scalar_text(value: &PyVal) -> (String, bool) {
    match value {
        PyVal::Null => ("null".to_owned(), true),
        PyVal::Bool(flag) => ((if *flag { "true" } else { "false" }).to_owned(), true),
        PyVal::Int(digits) => (digits.clone(), true),
        PyVal::Float(number) => (float_text(*number), true),
        PyVal::Str(text) => (text.clone(), implicit_scalar_tag(text) == TAG_STR),
        PyVal::List(_) | PyVal::Dict(_) => (String::new(), true),
    }
}

/// `Representer.represent_float`.
fn float_text(number: f64) -> String {
    if number.is_nan() {
        return ".nan".to_owned();
    }
    if number == f64::INFINITY {
        return ".inf".to_owned();
    }
    if number == f64::NEG_INFINITY {
        return "-.inf".to_owned();
    }
    let value = float_repr(number).to_lowercase();
    if !value.contains('.') && value.contains('e') {
        value.replacen('e', ".0e", 1)
    } else {
        value
    }
}

pub(super) fn escape(ch: char) -> String {
    let short = match ch {
        '\0' => '0',
        '\u{07}' => 'a',
        '\u{08}' => 'b',
        '\t' => 't',
        '\n' => 'n',
        '\u{0B}' => 'v',
        '\u{0C}' => 'f',
        '\r' => 'r',
        '\u{1B}' => 'e',
        '"' => '"',
        '\\' => '\\',
        '\u{85}' => 'N',
        '\u{A0}' => '_',
        '\u{2028}' => 'L',
        '\u{2029}' => 'P',
        _ => {
            let code = u32::from(ch);
            return if code <= 0xFF {
                format!("\\x{code:02X}")
            } else if code <= 0xFFFF {
                format!("\\u{code:04X}")
            } else {
                format!("\\U{code:08X}")
            };
        }
    };
    format!("\\{short}")
}
