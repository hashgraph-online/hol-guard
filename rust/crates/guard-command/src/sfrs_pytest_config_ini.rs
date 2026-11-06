//! `configparser.ConfigParser(interpolation=None, strict=True,
//! empty_lines_in_values=True)` as `pytest_config._parse_ini` drives it.
//!
//! Only what the pytest section read needs: the section lookup, the `DEFAULT`
//! merge and the strict duplicate checks. The reader follows CPython's
//! `RawConfigParser._read` line by line so continuation lines, comment lines
//! and error precedence match.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::codex_output_py::{is_py_space, py_rstrip, py_strip};

/// Why configparser refused the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IniError {
    /// `DuplicateSectionError` or `DuplicateOptionError`.
    Duplicate,
    /// `MissingSectionHeaderError` or `ParsingError` (any other `Error`).
    Syntax,
}

const DEFAULT_SECTION: &str = "DEFAULT";

type Options = BTreeMap<String, Vec<String>>;

/// `^\[(?P<header>.+)\]` matched against a stripped line.
fn section_header(value: &str) -> Option<&str> {
    let inner = value.strip_prefix('[')?;
    let end = inner.rfind(']')?;
    let header = &inner[..end];
    (!header.is_empty() && !header.contains('\n')).then_some(header)
}

/// `(?P<option>.*?)\s*(?P<vi>=|:)\s*(?P<value>.*)$` matched against a stripped
/// line: the option ends at the first delimiter.
fn option_line(value: &str) -> Option<(&str, &str)> {
    let index = value.find(['=', ':'])?;
    let option = py_rstrip(&value[..index]);
    let rest = &value[index + 1..];
    let rest = rest.trim_start_matches(is_py_space);
    Some((option, rest))
}

fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| is_py_space(*c)).count()
}

/// Options of `section` (with `DEFAULT` merged under them), or `None` when the
/// text defines no such section. `Err` is the exception class configparser
/// raises while reading.
pub(crate) fn parse_ini_section(
    text: &str,
    section: &str,
) -> Result<Option<BTreeMap<String, String>>, IniError> {
    let mut defaults: Options = Options::new();
    let mut sections: Vec<(String, Options)> = Vec::new();
    let mut elements_sections: BTreeSet<String> = BTreeSet::new();
    let mut elements_options: BTreeSet<(String, String)> = BTreeSet::new();
    // Index into `sections`, or `usize::MAX` for the defaults.
    let mut current: Option<usize> = None;
    let mut sect_name = String::new();
    let mut option_name: Option<String> = None;
    let mut indent_level = 0usize;
    let mut pending_error = false;

    for line in text.split_inclusive('\n') {
        let stripped = py_strip(line);
        let comment = stripped.starts_with('#') || stripped.starts_with(';');
        let value = if comment { "" } else { stripped };
        if value.is_empty() {
            if !comment {
                if let (Some(index), Some(name)) = (current, option_name.as_ref()) {
                    if !name.is_empty() {
                        let options = options_mut(&mut defaults, &mut sections, index);
                        if let Some(lines) = options.get_mut(name) {
                            lines.push(String::new());
                        }
                    }
                }
            }
            continue;
        }
        let current_indent = indent_of(line);
        let continuation = match (&current, &option_name) {
            (Some(_), Some(name)) => !name.is_empty() && current_indent > indent_level,
            _ => false,
        };
        if continuation {
            let index = current.expect("section");
            let name = option_name.clone().expect("option");
            let options = options_mut(&mut defaults, &mut sections, index);
            if let Some(lines) = options.get_mut(&name) {
                lines.push(value.to_owned());
            }
            continue;
        }
        indent_level = current_indent;
        if let Some(header) = section_header(value) {
            sect_name = header.to_owned();
            if sections.iter().any(|(name, _)| *name == sect_name) {
                return Err(IniError::Duplicate);
            }
            if sect_name == DEFAULT_SECTION {
                current = Some(usize::MAX);
            } else {
                sections.push((sect_name.clone(), Options::new()));
                elements_sections.insert(sect_name.clone());
                current = Some(sections.len() - 1);
            }
            option_name = None;
        } else if current.is_none() {
            return Err(IniError::Syntax);
        } else if let Some((raw_name, raw_value)) = option_line(value) {
            let name = raw_name.to_lowercase();
            if raw_name.is_empty() {
                pending_error = true;
            }
            let key = (sect_name.clone(), name.clone());
            if elements_options.contains(&key) {
                return Err(IniError::Duplicate);
            }
            elements_options.insert(key);
            let index = current.expect("section");
            let options = options_mut(&mut defaults, &mut sections, index);
            options.insert(name.clone(), vec![py_strip(raw_value).to_owned()]);
            option_name = Some(name);
        } else {
            pending_error = true;
        }
    }
    if pending_error {
        return Err(IniError::Syntax);
    }
    let Some((_, own)) = sections.iter().find(|(name, _)| name == section) else {
        return Ok(None);
    };
    let join = |options: &Options| -> BTreeMap<String, String> {
        options
            .iter()
            .map(|(name, lines)| (name.clone(), py_rstrip(&lines.join("\n")).to_owned()))
            .collect()
    };
    let mut merged = join(&defaults);
    merged.extend(join(own));
    Ok(Some(merged))
}

fn options_mut<'a>(
    defaults: &'a mut Options,
    sections: &'a mut [(String, Options)],
    index: usize,
) -> &'a mut Options {
    if index == usize::MAX {
        defaults
    } else {
        &mut sections[index].1
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_ini_section, IniError};

    #[test]
    fn reads_section_with_defaults() {
        let parsed = parse_ini_section("[DEFAULT]\na = 1\n[pytest]\nB: two\n", "pytest")
            .expect("ok")
            .expect("section");
        assert_eq!(parsed["a"], "1");
        assert_eq!(parsed["b"], "two");
    }

    #[test]
    fn strict_duplicates_are_reported() {
        assert_eq!(
            parse_ini_section("[a]\nx=1\nx=2\n", "a"),
            Err(IniError::Duplicate)
        );
        assert_eq!(
            parse_ini_section("[a]\n[a]\n", "a"),
            Err(IniError::Duplicate)
        );
        assert_eq!(parse_ini_section("x=1\n", "a"), Err(IniError::Syntax));
    }
}
