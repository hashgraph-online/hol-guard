//! What a file's `.replace` calls can do to the filesystem. A path's
//! `replace(target)` moves the file onto `target`; called on a path class,
//! `Path.replace(source, target)` takes the same two arguments as the string
//! and bytes forms, so a two-argument call moves a file only when the code
//! can reach a path class as a value.

use std::sync::OnceLock;

use regex::Regex;

use super::pattern;

/// What the `.replace` calls and path class uses in one file allow.
#[derive(Default, Clone, Copy)]
pub(in super::super) struct Replaces {
    /// A call that moves a file whatever its receiver: one argument, a
    /// starred one, a call that never closes, or the method taken as a value.
    pub(in super::super) moves: bool,
    /// A call with two or more arguments.
    pub(in super::super) pairs: bool,
    /// A path class used as a value rather than built or named in a type.
    pub(in super::super) classes: bool,
}

impl Replaces {
    pub(in super::super) fn join(self, other: Replaces) -> Replaces {
        Replaces {
            moves: self.moves || other.moves,
            pairs: self.pairs || other.pairs,
            classes: self.classes || other.classes,
        }
    }

    pub(in super::super) fn writes(self) -> bool {
        self.moves || (self.pairs && self.classes)
    }
}

fn replace_attribute() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\.\s*replace\b")
}

fn path_class() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"\b(?:PurePosixPath|PureWindowsPath|PosixPath|WindowsPath|PurePath|Path)\b",
    )
}

/// `type(value)` returns a value's class, and the bare name aliases `type`.
fn type_builtin() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"(?m)(?:^|[^.\w])type\b[ \t]*(?:[^=\s]|==|$)")
}

/// A `from pathlib import` that names its classes without renaming them.
fn pathlib_import() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"(?m)^[ \t]*from[ \t]+pathlib[ \t]+import[ \t]*(?:\([^)]*\)|[^\n;]*)",
    )
}

fn renames() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bas\b")
}

fn definition_head() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bdef\s+\w+\s*$")
}

fn statement_target() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^\s*[A-Za-z_][\w.]*\s*$")
}

fn defines_add_argument() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\bdef\s+add_argument\b")
}

/// The byte ranges of the arguments of the call whose parentheses open just
/// before `start`, or `None` when the call does not close.
pub(super) fn call_arguments(code: &str, start: usize) -> Option<Vec<std::ops::Range<usize>>> {
    let mut depth = 0usize;
    let mut arguments = Vec::new();
    let mut from = start;
    for (offset, byte) in code[start..].bytes().enumerate() {
        let at = start + offset;
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            b')' => {
                arguments.push(from..at);
                return Some(arguments);
            }
            b',' if depth == 0 => {
                arguments.push(from..at);
                from = at + 1;
            }
            _ => {}
        }
    }
    None
}

/// The bracket that encloses `at`, if any.
fn enclosing(code: &str, at: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in code[..at].bytes().enumerate().rev() {
        match byte {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth == 0 => return Some(index),
            b'(' | b'[' | b'{' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn is_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

/// Whether the name starting at `start` sits where Python reads it as a
/// type rather than a value: a return annotation, a parameter or statement
/// annotation, or a type argument of a subscript that is itself one.
fn annotation(code: &str, start: usize) -> bool {
    let before = code[..start].trim_end();
    if before.ends_with("->") {
        return true;
    }
    if let Some(head) = before.strip_suffix(':') {
        return match enclosing(code, head.len()) {
            Some(open) => {
                code.as_bytes()[open] == b'(' && definition_head().is_match(&code[..open])
            }
            None => statement_target().is_match(&head[head.rfind('\n').map_or(0, |at| at + 1)..]),
        };
    }
    if before.ends_with('[') || before.ends_with(',') {
        if let Some(open) = enclosing(code, start) {
            if code.as_bytes()[open] == b'[' {
                let head = code[..open].trim_end();
                let name = head.trim_end_matches(|c: char| c == '.' || is_word(c as u8));
                if name.len() < head.len() {
                    return annotation(code, name.len());
                }
            }
        }
    }
    false
}

/// Whether the call whose arguments hold `start` takes the class as data it
/// only calls: the type of `isinstance`, or an `argparse` argument type.
fn checked_or_parsed(code: &str, start: usize, end: usize) -> bool {
    let Some(open) = enclosing(code, start) else {
        return false;
    };
    let head = code[..open].trim_end();
    let before = code[..start].trim_end();
    let last = code[end..].trim_start().starts_with(')');
    let isinstance = (head.ends_with("isinstance") || head.ends_with("issubclass"))
        && before.ends_with(',')
        && last;
    let parsed = head.ends_with(".add_argument")
        && before
            .strip_suffix('=')
            .is_some_and(|rest| rest.trim_end().ends_with("type"))
        && !defines_add_argument().is_match(code);
    isinstance || parsed
}

/// Whether some path class name in `code` is used as a value.
fn reaches_class(original: &str) -> bool {
    let mut code = original.to_owned();
    for found in pathlib_import().find_iter(original) {
        if !renames().is_match(found.as_str()) {
            code.replace_range(found.range(), &" ".repeat(found.len()));
        }
    }
    if type_builtin().is_match(&code) {
        return true;
    }
    path_class().find_iter(&code).any(|found| {
        let after = code[found.end()..].trim_start();
        if after.starts_with('(') {
            return false;
        }
        if let Some(rest) = after.strip_prefix('.') {
            let attribute: String = rest
                .trim_start()
                .bytes()
                .take_while(|byte| is_word(*byte))
                .map(char::from)
                .collect();
            return attribute == "replace";
        }
        !annotation(&code, found.start()) && !checked_or_parsed(&code, found.start(), found.end())
    })
}

/// `action.type` and `field.type` hand back a class that was only named as
/// data, including `add_argument(type=Path)` and a dataclass annotation.
fn type_attribute_receiver(code: &str, dot: usize) -> bool {
    code[..dot].trim_end().ends_with(".type")
}

pub(super) fn replaces(code: &str) -> Replaces {
    let mut found = Replaces {
        classes: reaches_class(code),
        ..Replaces::default()
    };
    for attribute in replace_attribute().find_iter(code) {
        let rest = &code[attribute.end()..];
        let Some(open) = rest
            .find(|c: char| !c.is_whitespace())
            .filter(|at| rest[*at..].starts_with('('))
        else {
            found.moves = true;
            continue;
        };
        match call_arguments(code, attribute.end() + open + 1) {
            None => found.moves = true,
            Some(arguments) => {
                let arguments: Vec<&str> = arguments
                    .into_iter()
                    .map(|range| code[range].trim())
                    .filter(|argument| !argument.is_empty())
                    .collect();
                if arguments.len() < 2
                    || arguments.iter().any(|argument| argument.starts_with('*'))
                    || type_attribute_receiver(code, attribute.start())
                {
                    found.moves = true;
                } else {
                    found.pairs = true;
                }
            }
        }
    }
    found
}
