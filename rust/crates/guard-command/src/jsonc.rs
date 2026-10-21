//! Port of `runtime/jsonc.py` — bounded JSON-with-comments decoder used by
//! Bun lockfiles (`bun.lock`).
//!
//! `normalize_jsonc` replaces JSONC syntax with whitespace without changing
//! character offsets (:22-24). Both passes are byte-indexed over the string;
//! Python iterates Unicode code points — the port operates on `Vec<char>` so
//! offsets inside the comment/comma scanner match Python one-for-one.
//!
//! `loads_jsonc` without `object_pairs_hook` maps to `serde_json::Value`.
//! The duplicate-key `object_pairs_hook` variant (`_unique_json_pairs` in
//! package_evidence_common) is exposed via `loads_jsonc_pairs`, which returns
//! raw pair lists — callers that need duplicates preserved MUST use it.

use serde_json::Value;

/// `loads_jsonc` (:10-19) — plain object parse (duplicate keys collapse,
/// serde_json default, matching Python's dict-without-hook).
pub fn loads_jsonc(text: &str) -> Result<Value, JsoncError> {
    let normalized = normalize_jsonc(text)?;
    serde_json::from_str(&normalized).map_err(|error| JsoncError::Decode(error.to_string()))
}

/// `loads_jsonc` with `deadline_check` — check fires every 4096 characters
/// during each normalization pass plus once at the end of each pass (:33,
/// :69, :79-80, :89-90, :109-110). `serde_json` performs the final parse
/// without periodic checks (Python's `json.loads` does the same — no hook
/// inside the C parser either).
pub fn loads_jsonc_with_deadline<F>(text: &str, mut deadline_check: F) -> Result<Value, JsoncError>
where
    F: FnMut() -> Result<(), JsoncError>,
{
    let normalized = normalize_jsonc_checked(text, &mut deadline_check)?;
    serde_json::from_str(&normalized).map_err(|error| JsoncError::Decode(error.to_string()))
}

/// `loads_jsonc` with `object_pairs_hook` (:10-19): parse preserving object
/// pair order/duplicates. Returns a lightweight pair-tree rather than
/// `serde_json::Value` — Python's hook receives `list[tuple[str, object]]`.
pub fn loads_jsonc_pairs(text: &str) -> Result<JsoncPairs, JsoncError> {
    let normalized = normalize_jsonc(text)?;
    parse_pairs(&normalized)
}

/// `loads_jsonc_pairs` with `deadline_check` — same periodic-check cadence as
/// `loads_jsonc_with_deadline` during normalization, preserving object pairs.
pub fn loads_jsonc_pairs_checked<F>(
    text: &str,
    deadline_check: &mut F,
) -> Result<JsoncPairs, JsoncError>
where
    F: FnMut() -> Result<(), JsoncError>,
{
    let normalized = normalize_jsonc_checked(text, deadline_check)?;
    parse_pairs(&normalized)
}

/// Error surface: `JsoncError::Decode` carries the `json.JSONDecodeError`
/// message shape (unterminated block comment reuses Python's exact message).
#[derive(Debug)]
pub enum JsoncError {
    Decode(String),
    Deadline(String),
}

impl std::fmt::Display for JsoncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsoncError::Decode(message) | JsoncError::Deadline(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for JsoncError {}

/// Pair-preserving JSON value for `object_pairs_hook` callers.
#[derive(Clone, Debug, PartialEq)]
pub enum JsoncPairs {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsoncPairs>),
    /// `(key, value)` pairs in document order — duplicates preserved.
    Object(Vec<(String, JsoncPairs)>),
}

/// `normalize_jsonc` (:22-24). Raises `JsoncError::Decode` on unterminated
/// block comment — Python raises `json.JSONDecodeError` at :75.
pub fn normalize_jsonc(text: &str) -> Result<String, JsoncError> {
    Ok(strip_trailing_commas(&strip_comments(text)?))
}

fn normalize_jsonc_checked<F>(text: &str, deadline_check: &mut F) -> Result<String, JsoncError>
where
    F: FnMut() -> Result<(), JsoncError>,
{
    let stripped = strip_comments_checked(text, deadline_check)?;
    strip_trailing_commas_checked(&stripped, deadline_check)
}

/// `_strip_comments` (:27-81).
fn strip_comments(text: &str) -> Result<String, JsoncError> {
    let mut none: Option<&mut dyn FnMut() -> Result<(), JsoncError>> = None;
    strip_comments_dyn(text, &mut none)
}
fn strip_comments_checked<F>(text: &str, deadline_check: &mut F) -> Result<String, JsoncError>
where
    F: FnMut() -> Result<(), JsoncError>,
{
    let mut slot: Option<&mut dyn FnMut() -> Result<(), JsoncError>> = Some(deadline_check);
    strip_comments_dyn(text, &mut slot)
}

fn strip_comments_dyn(
    text: &str,
    deadline_check: &mut Option<&mut dyn FnMut() -> Result<(), JsoncError>>,
) -> Result<String, JsoncError> {
    let chars: Vec<char> = text.chars().collect();
    let mut output = chars.clone();
    let mut in_string = false;
    let mut escaped = false;
    let mut index = 0usize;
    while index < chars.len() {
        if index % 4096 == 0 {
            if let Some(check) = deadline_check {
                check()?;
            }
        }
        let character = chars[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if character == '"' {
            in_string = true;
            index += 1;
            continue;
        }
        if character != '/' || index + 1 >= chars.len() {
            index += 1;
            continue;
        }
        let marker = chars[index + 1];
        if marker == '/' {
            output[index] = ' ';
            output[index + 1] = ' ';
            index += 2;
            while index < chars.len() && !matches!(chars[index], '\r' | '\n') {
                output[index] = ' ';
                index += 1;
            }
            continue;
        }
        if marker != '*' {
            index += 1;
            continue;
        }
        let comment_start = index;
        output[index] = ' ';
        output[index + 1] = ' ';
        index += 2;
        while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
            if index % 4096 == 0 {
                if let Some(check) = deadline_check {
                    check()?;
                }
            }
            output[index] = ' ';
            index += 1;
        }
        if index + 1 >= chars.len() {
            // :75 — Python raises JSONDecodeError("Unterminated block
            // comment", text, comment_start); keep the message verbatim.
            return Err(JsoncError::Decode(format!(
                "Unterminated block comment: line 1 column {} (char {})",
                comment_start + 1,
                comment_start
            )));
        }
        output[index] = ' ';
        output[index + 1] = ' ';
        index += 2;
    }
    if let Some(check) = deadline_check {
        check()?;
    }
    Ok(output.into_iter().collect())
}

/// `_strip_trailing_commas` (:84-111).
fn strip_trailing_commas(text: &str) -> String {
    let mut none: Option<&mut dyn FnMut() -> Result<(), JsoncError>> = None;
    strip_trailing_commas_dyn(text, &mut none).expect("no deadline check registered")
}

fn strip_trailing_commas_checked<F>(
    text: &str,
    deadline_check: &mut F,
) -> Result<String, JsoncError>
where
    F: FnMut() -> Result<(), JsoncError>,
{
    let mut slot: Option<&mut dyn FnMut() -> Result<(), JsoncError>> = Some(deadline_check);
    strip_trailing_commas_dyn(text, &mut slot)
}

fn strip_trailing_commas_dyn(
    text: &str,
    deadline_check: &mut Option<&mut dyn FnMut() -> Result<(), JsoncError>>,
) -> Result<String, JsoncError> {
    let chars: Vec<char> = text.chars().collect();
    let mut output = chars.clone();
    let mut in_string = false;
    let mut escaped = false;
    for index in 0..chars.len() {
        if index % 4096 == 0 {
            if let Some(check) = deadline_check {
                check()?;
            }
        }
        let character = chars[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            continue;
        }
        if character != ',' {
            continue;
        }
        let mut next_index = index + 1;
        // `isspace()` — Python Unicode whitespace; char::is_whitespace differs
        // only on \x1c-\x1f (Python-space, Unicode-not); file-separator chars
        // inside JSON are invalid input either way — the divergence is
        // unreachable on well-formed JSONC.
        while next_index < chars.len() && python_isspace(chars[next_index]) {
            next_index += 1;
        }
        if next_index < chars.len() && matches!(chars[next_index], '}' | ']') {
            output[index] = ' ';
        }
    }
    if let Some(check) = deadline_check {
        check()?;
    }
    Ok(output.into_iter().collect())
}

/// Python `str.isspace()` = Unicode whitespace + \x1c..\x1f.
fn python_isspace(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// Minimal recursive-descent pair-preserving JSON parser for
/// `loads_jsonc_pairs`. Input is the normalized JSONC output, so comments and
/// trailing commas are already whitespace.
fn parse_pairs(text: &str) -> Result<JsoncPairs, JsoncError> {
    let chars: Vec<char> = text.chars().collect();
    let mut parser = PairParser {
        chars: &chars,
        index: 0,
    };
    parser.skip_ws();
    let value = parser.value()?;
    parser.skip_ws();
    if parser.index != chars.len() {
        return Err(JsoncError::Decode(format!(
            "Extra data: line 1 column {} (char {})",
            parser.index + 1,
            parser.index
        )));
    }
    Ok(value)
}

struct PairParser<'a> {
    chars: &'a [char],
    index: usize,
}

impl<'a> PairParser<'a> {
    fn fail<T>(&self, message: &str) -> Result<T, JsoncError> {
        Err(JsoncError::Decode(format!(
            "{}: line 1 column {} (char {})",
            message,
            self.index + 1,
            self.index
        )))
    }

    fn skip_ws(&mut self) {
        while self.index < self.chars.len()
            && matches!(self.chars[self.index], ' ' | '\t' | '\n' | '\r')
        {
            self.index += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn value(&mut self) -> Result<JsoncPairs, JsoncError> {
        match self.peek() {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => Ok(JsoncPairs::String(self.string()?)),
            Some('t') | Some('f') => self.boolean(),
            Some('n') => self.null(),
            Some('-') | Some('0'..='9') => self.number(),
            _ => self.fail("Expecting value"),
        }
    }

    fn literal(&mut self, text: &str) -> Result<(), JsoncError> {
        for expected in text.chars() {
            if self.peek() != Some(expected) {
                return self.fail("Expecting value");
            }
            self.index += 1;
        }
        Ok(())
    }

    fn null(&mut self) -> Result<JsoncPairs, JsoncError> {
        self.literal("null")?;
        Ok(JsoncPairs::Null)
    }

    fn boolean(&mut self) -> Result<JsoncPairs, JsoncError> {
        match self.peek() {
            Some('t') => {
                self.literal("true")?;
                Ok(JsoncPairs::Bool(true))
            }
            _ => {
                self.literal("false")?;
                Ok(JsoncPairs::Bool(false))
            }
        }
    }

    fn number(&mut self) -> Result<JsoncPairs, JsoncError> {
        let start = self.index;
        if self.peek() == Some('-') {
            self.index += 1;
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.index += 1;
        }
        if self.peek() == Some('.') {
            self.index += 1;
            while matches!(self.peek(), Some('0'..='9')) {
                self.index += 1;
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.index += 1;
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.index += 1;
            }
            while matches!(self.peek(), Some('0'..='9')) {
                self.index += 1;
            }
        }
        let text: String = self.chars[start..self.index].iter().collect();
        text.parse::<f64>()
            .map(JsoncPairs::Number)
            .map_err(|_| JsoncError::Decode(format!("Expecting value: char {start}")))
    }

    fn string(&mut self) -> Result<String, JsoncError> {
        // Delegate to serde_json for escape/unicode parity: re-serialize the
        // raw token span then decode it with serde_json.
        let start = self.index;
        debug_assert_eq!(self.peek(), Some('"'));
        self.index += 1;
        let mut escaped = false;
        while self.index < self.chars.len() {
            let c = self.chars[self.index];
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                break;
            }
            self.index += 1;
        }
        if self.index >= self.chars.len() {
            return self.fail("Unterminated string starting at");
        }
        let raw: String = self.chars[start..=self.index].iter().collect();
        self.index += 1;
        serde_json::from_str::<String>(&raw)
            .map_err(|error| JsoncError::Decode(format!("Invalid \\escape: {error}")))
    }

    fn array(&mut self) -> Result<JsoncPairs, JsoncError> {
        self.index += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.index += 1;
            return Ok(JsoncPairs::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.index += 1;
                }
                Some(']') => {
                    self.index += 1;
                    return Ok(JsoncPairs::Array(items));
                }
                _ => return self.fail("Expecting ',' delimiter"),
            }
        }
    }

    fn object(&mut self) -> Result<JsoncPairs, JsoncError> {
        self.index += 1; // consume '{'
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.index += 1;
            return Ok(JsoncPairs::Object(pairs));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return self.fail("Expecting property name enclosed in double quotes");
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(':') {
                return self.fail("Expecting ':' delimiter");
            }
            self.index += 1;
            self.skip_ws();
            let value = self.value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.index += 1;
                }
                Some('}') => {
                    self.index += 1;
                    return Ok(JsoncPairs::Object(pairs));
                }
                _ => return self.fail("Expecting ',' delimiter"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_offsets_preserved_python_oracle() {
        // oracle: python3 jsonc.normalize_jsonc
        let cases: &[(&str, &str)] = &[
            (
                "{\"a\":1, // trailing\n \"b\": [1,2,], /* blk */ \"c\": \"x // y\",}",
                "{\"a\":1,            \n \"b\": [1,2 ],           \"c\": \"x // y\" }",
            ),
            ("{\"k\":\"v\",}", "{\"k\":\"v\" }"),
            ("{\"url\": \"http://a/b\"}", "{\"url\": \"http://a/b\"}"),
            ("{\"a\":1}//eof comment", "{\"a\":1}             "),
            ("[1,2,\r\n3]", "[1,2,\r\n3]"),
            (
                "{\"esc\": \"a\\\"b\", \"n\": 2,}",
                "{\"esc\": \"a\\\"b\", \"n\": 2 }",
            ),
        ];
        for (input, expected) in cases {
            let got = normalize_jsonc(input).unwrap();
            assert_eq!(got, *expected, "input: {input:?}");
            // offsets preserved: same char length as input
            assert_eq!(got.chars().count(), input.chars().count());
        }
    }

    #[test]
    fn unterminated_block_comment_raises() {
        let err = loads_jsonc("{\"a\":1 /* dangling").unwrap_err();
        assert!(err.to_string().starts_with("Unterminated block comment"));
    }

    #[test]
    fn loads_parses_bun_style_lock() {
        let text = "{ \"lockfileVersion\": 1, // comment\n \"workspaces\": {}, }";
        let value = loads_jsonc(text).unwrap();
        assert_eq!(value["lockfileVersion"], 1);
    }

    #[test]
    fn pairs_preserve_duplicate_keys() {
        let text = "{\"a\": 1, \"a\": 2}";
        let JsoncPairs::Object(pairs) = loads_jsonc_pairs(text).unwrap() else {
            panic!("object expected");
        };
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "a");
        assert_eq!(pairs[0].1, JsoncPairs::Number(1.0));
        assert_eq!(pairs[1].1, JsoncPairs::Number(2.0));
    }

    #[test]
    fn deadline_check_fires() {
        let mut fired = false;
        let text = format!("{{\"k\": \"{}\"}}", "x".repeat(9000));
        let value = loads_jsonc_with_deadline(&text, || {
            fired = true;
            Ok(())
        })
        .unwrap();
        assert!(fired);
        assert_eq!(value["k"].as_str().unwrap().len(), 9000);
    }
}
