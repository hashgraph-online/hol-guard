//! The origin URL `_read_origin_remote` (`project_identity.py`) reads from a
//! Git config: `RawConfigParser(interpolation=None, strict=False,
//! allow_no_value=True).read_string(content)` (CPython `_read`), then
//! `get('remote "origin"', "url", fallback=None)`, stripped.
//!
//! `Ok(None)` is a parse the Python reader answers with `None`; `Unmirrored`
//! is one whose Python outcome this reader does not reproduce exactly.

use crate::context_digest::{is_python_space, python_strip};
use crate::project_identity::{Mirror, Unmirrored};
use std::collections::HashMap;

const ORIGIN_SECTION: &str = "remote \"origin\"";
const DEFAULT_SECTION: &str = "DEFAULT";
const URL_OPTION: &str = "url";

/// An option's value lines, or `None` for a valueless option.
type Lines = Option<Vec<String>>;
type Options = HashMap<String, Lines>;

/// The section the parser is reading.
#[derive(Clone)]
enum Cursor {
    Defaults,
    Named(String),
}

#[derive(Default)]
struct Parsed {
    defaults: Options,
    sections: HashMap<String, Options>,
}

impl Parsed {
    fn options(&mut self, cursor: &Cursor) -> &mut Options {
        match cursor {
            Cursor::Defaults => &mut self.defaults,
            Cursor::Named(name) => self.sections.entry(name.clone()).or_default(),
        }
    }
}

/// `SECTCRE` (`\[(?P<header>.+)\]`) matched at the start of a stripped
/// line: the greedy header runs to the last `]`.
fn section_header(value: &str) -> Option<&str> {
    let rest = value.strip_prefix('[')?;
    let close = rest.rfind(']')?;
    (close > 0).then(|| &rest[..close])
}

/// `OPTCRE_NV` on a stripped line: the lazy option ends at the whitespace
/// run before the first delimiter; the value follows it.
fn option_line(value: &str) -> (&str, Option<&str>) {
    match value.find(['=', ':']) {
        Some(at) => (
            value[..at].trim_end_matches(is_python_space),
            Some(&value[at + 1..]),
        ),
        None => (value, None),
    }
}

/// Python's universal-newline read: `\r\n` and `\r` both become `\n`.
fn universal_newlines(content: &str) -> String {
    content.replace("\r\n", "\n").replace('\r', "\n")
}

/// The stripped origin URL, as `_read_origin_remote` returns it.
pub(crate) fn origin_url(content: &str) -> Mirror<Option<String>> {
    let content = universal_newlines(content);
    let mut parsed = Parsed::default();
    let mut cursor: Option<Cursor> = None;
    let mut option: Option<String> = None;
    let mut indent_level = 0usize;
    let mut parse_error = false;
    // `io.StringIO` yields lines split on `\n` only, each keeping its `\n`.
    for line in content.split_inclusive('\n') {
        let stripped = python_strip(line);
        let comment = stripped.starts_with('#') || stripped.starts_with(';');
        if comment || stripped.is_empty() {
            // An empty line extends the open value; a comment line does not.
            if let (false, Some(sect), Some(name)) = (comment, &cursor, &option) {
                if let Some(Some(lines)) = parsed.options(sect).get_mut(name) {
                    lines.push(String::new());
                }
            }
            continue;
        }
        let indent = line
            .chars()
            .position(|ch| !is_python_space(ch))
            .unwrap_or(0);
        if let (Some(sect), Some(name)) = (&cursor, &option) {
            if !name.is_empty() && indent > indent_level {
                match parsed.options(sect).get_mut(name) {
                    Some(Some(lines)) => lines.push(stripped.to_owned()),
                    // A continuation of a valueless option raises a
                    // version-specific error (AttributeError before 3.13).
                    _ => return Err(Unmirrored),
                }
                continue;
            }
        }
        indent_level = indent;
        if let Some(header) = section_header(stripped) {
            cursor = Some(if parsed.sections.contains_key(header) {
                Cursor::Named(header.to_owned())
            } else if header == DEFAULT_SECTION {
                Cursor::Defaults
            } else {
                parsed.sections.insert(header.to_owned(), Options::new());
                Cursor::Named(header.to_owned())
            });
            option = None;
            continue;
        }
        let Some(sect) = cursor.clone() else {
            // MissingSectionHeaderError, a `configparser.Error`:
            // project_identity.py:_read_origin_remote returns None.
            return Ok(None);
        };
        let (name, value) = option_line(stripped);
        // An empty option name is a ParsingError raised after the read.
        parse_error |= name.is_empty();
        let name = name.to_lowercase();
        let lines = value.map(|value| vec![python_strip(value).to_owned()]);
        parsed.options(&sect).insert(name.clone(), lines);
        option = Some(name);
    }
    if parse_error {
        // ParsingError, a `configparser.Error`:
        // project_identity.py:_read_origin_remote returns None.
        return Ok(None);
    }
    let Some(origin) = parsed.sections.get(ORIGIN_SECTION) else {
        // project_identity.py:_read_origin_remote: no origin section, so the
        // `fallback=None` answer.
        return Ok(None);
    };
    let Some(Some(lines)) = origin
        .get(URL_OPTION)
        .or_else(|| parsed.defaults.get(URL_OPTION))
    else {
        // project_identity.py:_read_origin_remote: a missing or valueless
        // url is not a string.
        return Ok(None);
    };
    let joined = lines.join("\n");
    let url = python_strip(joined.trim_end_matches(is_python_space));
    // project_identity.py:_read_origin_remote: an empty url is None.
    Ok((!url.is_empty()).then(|| url.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_split_at_the_first_delimiter() {
        assert_eq!(option_line("a = b = c"), ("a", Some(" b = c")));
        assert_eq!(option_line("url:https://h/p"), ("url", Some("https://h/p")));
        assert_eq!(option_line("= x"), ("", Some(" x")));
        assert_eq!(option_line("bare"), ("bare", None));
    }

    #[test]
    fn headers_run_to_the_last_bracket() {
        assert_eq!(section_header("[a] # [b]"), Some("a] # [b"));
        assert_eq!(section_header("[]x"), None);
        assert_eq!(section_header("[]]"), Some("]"));
        assert_eq!(section_header("x[a]"), None);
    }

    #[test]
    fn a_valueless_continuation_is_unmirrored() {
        assert_eq!(
            origin_url("[remote \"origin\"]\nbare\n\tmore\n"),
            Err(Unmirrored)
        );
    }
}
