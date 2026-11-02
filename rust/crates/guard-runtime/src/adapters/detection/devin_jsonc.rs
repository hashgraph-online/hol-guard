//! `runner_authority` kind `devin_jsonc` and the JSONC rules `devin_detect`
//! reads Devin's config files with: `//` and `/* */` comments and trailing
//! commas outside strings are stripped when strict JSON fails. The kind
//! answers `parse_devin_jsonc` for one captured config text: which text Python
//! decodes into the payload, and the `had_comments` and `parse_failed` flags.
//! Input CPython raises on instead of parsing (an oversized integer, nesting
//! past the depth limit) is refused.

use serde_json::{json, Value};

use super::adapter_inventory::ERR_VALUE;
use super::context_digest::python_strip;
use super::pyjson::{
    parse_mapping_lone_surrogates, parse_marking_lone_surrogates, JsonFailure, PyVal,
};
use super::runner_authority_op::{KindResult, ERR_INVALID};

/// One `parse_devin_jsonc` outcome. `source` is the text whose object is the
/// payload, `None` for an empty payload.
pub(crate) struct Parsed {
    pub(crate) payload: PyVal,
    pub(crate) source: Option<String>,
    pub(crate) had_comments: bool,
    pub(crate) parse_failed: bool,
}

/// `{"text": <config text>}` to `{"source", "had_comments", "parse_failed"}`.
pub(crate) fn document(args: &Value) -> KindResult {
    let text = args
        .as_object()
        .filter(|fields| fields.len() == 1)
        .and_then(|fields| fields.get("text"))
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    // Python decodes `source` itself, so a lone surrogate CPython keeps in a
    // key or value only has to parse here, never to survive as a value.
    let parsed = parse_with(text, |text| {
        parse_mapping_lone_surrogates(text).map(|mapped| mapped.value)
    })?;
    Ok(json!({
        "source": parsed.source,
        "had_comments": parsed.had_comments,
        "parse_failed": parsed.parse_failed,
    }))
}

/// The end of the `//` or `/* */` comment that starts at `index`, if one does.
fn comment_end(chars: &[char], index: usize) -> Option<usize> {
    if chars[index] != '/' || index + 1 >= chars.len() {
        return None;
    }
    let mut end = index + 2;
    match chars[index + 1] {
        '/' => {
            while end < chars.len() && !matches!(chars[end], '\r' | '\n') {
                end += 1;
            }
            Some(end)
        }
        '*' => {
            while end + 1 < chars.len() && !(chars[end] == '*' && chars[end + 1] == '/') {
                end += 1;
            }
            Some(end + 2)
        }
        _ => None,
    }
}

/// `_strip_jsonc_syntax`: comments and trailing commas outside strings go.
fn strip_jsonc_syntax(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    while index < chars.len() {
        let character = chars[index];
        if in_string {
            output.push(character);
            if character == '\\' && index + 1 < chars.len() {
                output.push(chars[index + 1]);
                index += 2;
                continue;
            }
            in_string = character != '"';
            index += 1;
            continue;
        }
        if character == '"' {
            in_string = true;
            output.push(character);
            index += 1;
            continue;
        }
        if let Some(end) = comment_end(&chars, index) {
            index = end;
            continue;
        }
        if character == ',' {
            let mut lookahead = index + 1;
            while lookahead < chars.len() {
                if matches!(chars[lookahead], ' ' | '\t' | '\r' | '\n') {
                    lookahead += 1;
                } else if let Some(end) = comment_end(&chars, lookahead) {
                    lookahead = end;
                } else {
                    break;
                }
            }
            if lookahead < chars.len() && matches!(chars[lookahead], ']' | '}') {
                index += 1;
                continue;
            }
        }
        output.push(character);
        index += 1;
    }
    output
}

/// One `json.loads` attempt: `Ok(None)` on a syntax error, the object or an
/// unparsed marker otherwise. Integer-limit and depth failures raise in
/// Python, so they are refused.
fn loads(
    text: &str,
    parser: impl Fn(&str) -> Result<PyVal, JsonFailure>,
) -> Result<Option<Option<PyVal>>, &'static str> {
    match parser(text) {
        Ok(value @ PyVal::Dict(_)) => Ok(Some(Some(value))),
        Ok(_) => Ok(Some(None)),
        Err(JsonFailure::Syntax) => Ok(None),
        Err(_) => Err(ERR_VALUE),
    }
}

fn outcome(found: Option<(PyVal, String)>, had_comments: bool, parse_failed: bool) -> Parsed {
    let (payload, source) = match found {
        Some((payload, source)) => (payload, Some(source)),
        None => (PyVal::Dict(Vec::new()), None),
    };
    Parsed {
        payload,
        source,
        had_comments,
        parse_failed,
    }
}

/// `parse_devin_jsonc`, with a lone surrogate in a value marked by
/// `LONE_SURROGATE_MARK` and one in a key refused.
pub(crate) fn parse(text: &str) -> Result<Parsed, &'static str> {
    parse_with(text, parse_marking_lone_surrogates)
}

fn parse_with(
    text: &str,
    parser: impl Fn(&str) -> Result<PyVal, JsonFailure>,
) -> Result<Parsed, &'static str> {
    if python_strip(text).is_empty() {
        return Ok(outcome(None, false, false));
    }
    if let Some(parsed) = loads(text, &parser)? {
        let failed = parsed.is_none();
        let found = parsed.map(|payload| (payload, text.to_owned()));
        return Ok(outcome(found, false, failed));
    }
    let stripped = strip_jsonc_syntax(text);
    if python_strip(&stripped).is_empty() {
        return Ok(outcome(None, true, false));
    }
    Ok(match loads(&stripped, &parser)? {
        None => outcome(None, false, true),
        Some(None) => outcome(None, true, true),
        Some(Some(payload)) => outcome(Some((payload, stripped)), true, false),
    })
}

/// `devin_detect`'s view: the object a config holds, or `None` when it could
/// not be parsed.
pub(crate) fn parse_jsonc(text: &str) -> Result<Option<PyVal>, &'static str> {
    let parsed = parse(text)?;
    Ok((!parsed.parse_failed).then_some(parsed.payload))
}
