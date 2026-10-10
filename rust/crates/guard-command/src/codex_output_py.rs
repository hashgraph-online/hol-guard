//! Python text and path semantics shared by the Codex tool-output review.
//!
//! The retired Python review leaned on `str.strip`, `shlex.split`/`join`/
//! `quote` and `pathlib.PurePosixPath`. Rust reproduces exactly those
//! behaviours, edge cases included, so the ported decisions match the retired
//! implementation on every input.

use std::fmt;

/// Characters `str.isspace` accepts.
pub(crate) fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

/// `str.lstrip()`.
pub(crate) fn py_lstrip(text: &str) -> &str {
    text.trim_start_matches(is_py_space)
}

/// `str.rstrip()`.
pub(crate) fn py_rstrip(text: &str) -> &str {
    text.trim_end_matches(is_py_space)
}

/// `str.splitlines()` (line terminators only, no keepends).
pub(crate) fn py_splitlines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                lines.push(std::mem::take(&mut current));
            }
            '\n' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}'
            | '\u{2029}' => lines.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// `str.strip("'\"")`.
pub(crate) fn strip_quotes(text: &str) -> &str {
    text.trim_matches(|c| c == '\'' || c == '"')
}

/// `shlex.split(text)` (POSIX, no comments). `None` is Python's `ValueError`.
pub(crate) fn shlex_split(text: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut chars = text.chars();
    // States mirror `shlex.shlex.read_token`.
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Space,
        Word,
        Quote(char),
        Escape(Escaped),
    }
    #[derive(Clone, Copy, PartialEq)]
    enum Escaped {
        Word,
        Double,
    }
    let mut state = State::Space;
    let mut token = String::new();
    let mut quoted = false;
    loop {
        let next = chars.next();
        match state {
            State::Space => match next {
                None => break,
                Some(c) if is_shlex_space(c) => {}
                Some('\\') => state = State::Escape(Escaped::Word),
                Some(c @ ('\'' | '"')) => {
                    state = State::Quote(c);
                    quoted = true;
                }
                Some(c) => {
                    token.push(c);
                    state = State::Word;
                }
            },
            State::Word => match next {
                None => {
                    tokens.push(std::mem::take(&mut token));
                    break;
                }
                Some(c) if is_shlex_space(c) => {
                    tokens.push(std::mem::take(&mut token));
                    quoted = false;
                    state = State::Space;
                }
                Some('\\') => state = State::Escape(Escaped::Word),
                Some(c @ ('\'' | '"')) => {
                    state = State::Quote(c);
                    quoted = true;
                }
                Some(c) => token.push(c),
            },
            State::Quote(open) => match next {
                None => return None,
                Some(c) if c == open => state = State::Word,
                Some('\\') if open == '"' => state = State::Escape(Escaped::Double),
                Some(c) => token.push(c),
            },
            State::Escape(kind) => match next {
                None => return None,
                Some(c) => {
                    if kind == Escaped::Double && c != '\\' && c != '"' {
                        token.push('\\');
                    }
                    token.push(c);
                    state = match kind {
                        Escaped::Word => State::Word,
                        Escaped::Double => State::Quote('"'),
                    };
                }
            },
        }
    }
    let _ = quoted;
    Some(tokens)
}

fn is_shlex_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

pub(crate) use crate::command_launcher_floors::shlex_join;

/// A `pathlib.PurePosixPath`: root plus normalized components.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PyPath {
    root: &'static str,
    comps: Vec<String>,
}

impl PyPath {
    pub(crate) fn new(text: &str) -> Self {
        let root = if text.starts_with("//") && !text.starts_with("///") {
            "//"
        } else if text.starts_with('/') {
            "/"
        } else {
            ""
        };
        let comps = text
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned)
            .collect();
        Self { root, comps }
    }

    pub(crate) fn is_absolute(&self) -> bool {
        !self.root.is_empty()
    }

    /// `PurePosixPath.parts`.
    pub(crate) fn parts(&self) -> Vec<String> {
        let mut parts = Vec::with_capacity(self.comps.len() + 1);
        if !self.root.is_empty() {
            parts.push(self.root.to_owned());
        }
        parts.extend(self.comps.iter().cloned());
        parts
    }

    pub(crate) fn components(&self) -> &[String] {
        &self.comps
    }

    pub(crate) fn root(&self) -> &'static str {
        self.root
    }

    pub(crate) fn name(&self) -> &str {
        self.comps.last().map_or("", String::as_str)
    }

    pub(crate) fn suffix(&self) -> &str {
        let name = self.name();
        match name.rfind('.') {
            Some(index) if index > 0 && index < name.len() - 1 => &name[index..],
            _ => "",
        }
    }

    pub(crate) fn stem(&self) -> &str {
        let name = self.name();
        match name.rfind('.') {
            Some(index) if index > 0 && index < name.len() - 1 => &name[..index],
            _ => name,
        }
    }

    /// `self / other`.
    pub(crate) fn join(&self, other: &str) -> Self {
        let other = Self::new(other);
        if other.is_absolute() {
            return other;
        }
        let mut comps = self.comps.clone();
        comps.extend(other.comps);
        Self {
            root: self.root,
            comps,
        }
    }

    pub(crate) fn parent(&self) -> Self {
        let mut comps = self.comps.clone();
        comps.pop();
        Self {
            root: self.root,
            comps,
        }
    }

    /// `Path.relative_to` as a component list; `None` is `ValueError`.
    pub(crate) fn relative_to(&self, base: &Self) -> Option<Vec<String>> {
        if self.root != base.root || self.comps.len() < base.comps.len() {
            return None;
        }
        if self.comps[..base.comps.len()] != base.comps[..] {
            return None;
        }
        Some(self.comps[base.comps.len()..].to_vec())
    }

    pub(crate) fn pop_parent_components(&self) -> Vec<Self> {
        let mut parents = Vec::new();
        let mut current = self.clone();
        while !current.comps.is_empty() {
            current = current.parent();
            parents.push(current.clone());
        }
        parents
    }
}

impl fmt::Display for PyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.comps.is_empty() {
            return f.write_str(if self.root.is_empty() { "." } else { self.root });
        }
        write!(f, "{}{}", self.root, self.comps.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(text: &str) -> Option<Vec<String>> {
        shlex_split(text)
    }

    #[test]
    fn shlex_split_matches_python_edge_cases() {
        assert_eq!(split("a  b"), Some(vec!["a".into(), "b".into()]));
        assert_eq!(split("a ''"), Some(vec!["a".into(), String::new()]));
        assert_eq!(split("a\\ b"), Some(vec!["a b".into()]));
        assert_eq!(split("\"a\\$b\""), Some(vec!["a\\$b".into()]));
        assert_eq!(split("\"a\\\"b\""), Some(vec!["a\"b".into()]));
        assert_eq!(split("'a"), None);
        assert_eq!(split("a\\"), None);
        assert_eq!(split("a#b c"), Some(vec!["a#b".into(), "c".into()]));
        assert_eq!(split("a'b c'd"), Some(vec!["ab cd".into()]));
        assert_eq!(split("  "), Some(Vec::new()));
        assert_eq!(split("a\u{a0}b"), Some(vec!["a\u{a0}b".into()]));
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(py_splitlines("a\r\nb\n\nc"), vec!["a", "b", "", "c"]);
        assert_eq!(py_splitlines("a\u{85}b\u{2028}"), vec!["a", "b"]);
        assert!(py_splitlines("").is_empty());
        assert_eq!(py_splitlines("a\n"), vec!["a"]);
    }

    #[test]
    fn pure_path_matches_pathlib() {
        let path = PyPath::new("/a//b/./c.tar.gz");
        assert_eq!(path.parts(), vec!["/", "a", "b", "c.tar.gz"]);
        assert_eq!(path.name(), "c.tar.gz");
        assert_eq!(path.suffix(), ".gz");
        assert_eq!(path.stem(), "c.tar");
        assert_eq!(PyPath::new(".bashrc").suffix(), "");
        assert_eq!(PyPath::new("a.").suffix(), "");
        assert_eq!(PyPath::new("").to_string(), ".");
        assert_eq!(PyPath::new("//x").parts(), vec!["//", "x"]);
        assert_eq!(PyPath::new("///x").parts(), vec!["/", "x"]);
        assert_eq!(
            PyPath::new("/a/b/c").relative_to(&PyPath::new("/a")),
            Some(vec!["b".to_owned(), "c".to_owned()])
        );
        assert_eq!(PyPath::new("/a").relative_to(&PyPath::new("/b")), None);
        assert_eq!(PyPath::new("/a").join("b/../c").to_string(), "/a/b/../c");
    }
}
