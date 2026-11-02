//! Git's ignore rules for the prompt file walk, so a file a project keeps out
//! of Git never reaches an AI app as context. Reads `.git/info/exclude` and
//! the `.gitignore` in every folder the walk enters, without running `git`.
//!
//! Matching follows gitignore(5): blank lines and `#` comments are skipped,
//! `!` re-includes, a trailing `/` matches folders only, a pattern with a
//! slash before its end is anchored to its file's folder, and `*`, `?`,
//! `[...]` and `**` work as in Git. Deeper files override shallower ones and
//! the last matching line in a file wins. An ignore file that exists but
//! cannot be read keeps its whole folder out, rather than guessing.
use regex::{Regex, RegexBuilder};
use std::path::Path;
use std::rc::Rc;

const MAX_IGNORE_BYTES: usize = 65_536;
const MAX_RULES: usize = 1_024;

struct Rule {
    pattern: Regex,
    negated: bool,
    dir_only: bool,
    /// No slash before the end, so it matches the name at any depth.
    basename: bool,
}

/// The rules of one ignore file, for paths under `base` (relative to the
/// project root, empty at the top), and the files above it.
pub(crate) struct Ignores {
    base: String,
    rules: Vec<Rule>,
    parent: Chain,
}

pub(crate) type Chain = Option<Rc<Ignores>>;

/// The project's top-level rules, or `Err` when one exists but is unreadable.
pub(crate) fn root_chain(root: &Path) -> Result<Chain, ()> {
    let exclude = extend(None, &root.join(".git").join("info").join("exclude"), "")?;
    extend(exclude, &root.join(".gitignore"), "")
}

/// `chain` plus the ignore file at `file`, whose folder is `base` in the
/// project. `Err` when the file exists but cannot be read.
pub(crate) fn extend(chain: Chain, file: &Path, base: &str) -> Result<Chain, ()> {
    if std::fs::symlink_metadata(file).is_err() {
        return Ok(chain);
    }
    let read = guard_secure_fs::read_bounded(file, MAX_IGNORE_BYTES).map_err(|_| ())?;
    let text = String::from_utf8_lossy(&read.bytes);
    let rules: Vec<Rule> = text.lines().filter_map(parse).take(MAX_RULES).collect();
    if rules.is_empty() {
        return Ok(chain);
    }
    Ok(Some(Rc::new(Ignores {
        base: base.to_owned(),
        rules,
        parent: chain,
    })))
}

/// Whether `relative` (slash-separated, from the project root) is ignored.
pub(crate) fn ignored(chain: &Chain, relative: &str, is_dir: bool) -> bool {
    let mut next = chain.as_deref();
    while let Some(set) = next {
        if let Some(rest) = within(relative, &set.base) {
            let name = rest.rsplit('/').next().unwrap_or(rest);
            for rule in set.rules.iter().rev() {
                if rule.dir_only && !is_dir {
                    continue;
                }
                let subject = if rule.basename { name } else { rest };
                if rule.pattern.is_match(subject) {
                    return !rule.negated;
                }
            }
        }
        next = set.parent.as_deref();
    }
    false
}

fn within<'a>(relative: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() {
        return Some(relative);
    }
    relative.strip_prefix(base)?.strip_prefix('/')
}

fn parse(line: &str) -> Option<Rule> {
    let line = trim_trailing_spaces(line.strip_suffix('\r').unwrap_or(line));
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (negated, line) = match line.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (dir_only, line) = match line.strip_suffix('/') {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    if line.is_empty() {
        return None;
    }
    let basename = !line.contains('/');
    let line = line.strip_prefix('/').unwrap_or(line);
    // Git matches case-insensitively where the file system does by default.
    let pattern = RegexBuilder::new(&format!("^{}$", translate(line)))
        .case_insensitive(cfg!(any(windows, target_os = "macos")))
        .size_limit(1 << 20)
        .build()
        .ok()?;
    Some(Rule {
        pattern,
        negated,
        dir_only,
        basename,
    })
}

/// Trailing spaces are dropped unless escaped with a backslash.
fn trim_trailing_spaces(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b' ' {
        if end >= 2 && bytes[end - 2] == b'\\' {
            break;
        }
        end -= 1;
    }
    &line[..end]
}

/// The glob as a regular expression over a slash-separated path.
fn translate(glob: &str) -> String {
    let chars: Vec<char> = glob.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if chars.get(i + 1) == Some(&'*') => {
                let mut end = i;
                while chars.get(end) == Some(&'*') {
                    end += 1;
                }
                let starts_part = i == 0 || chars[i - 1] == '/';
                if starts_part && end == chars.len() {
                    out.push_str(".*");
                    i = end;
                } else if starts_part && chars.get(end) == Some(&'/') {
                    out.push_str("(?:.*/)?");
                    i = end + 1;
                } else {
                    out.push_str("[^/]*");
                    i = end;
                }
            }
            '*' => {
                out.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            '[' => match class(&chars[i + 1..]) {
                Some((class, used)) => {
                    out.push_str(&class);
                    i += used + 1;
                }
                None => {
                    out.push_str("\\[");
                    i += 1;
                }
            },
            '\\' if i + 1 < chars.len() => {
                out.push_str(&regex::escape(&chars[i + 1].to_string()));
                i += 2;
            }
            other => {
                out.push_str(&regex::escape(&other.to_string()));
                i += 1;
            }
        }
    }
    out
}

/// A bracket expression after its `[`, as a regex class, and the number of
/// characters it used; `None` when it never closes, so `[` is literal.
fn class(rest: &[char]) -> Option<(String, usize)> {
    let mut out = String::from("[");
    let mut i = 0;
    if matches!(rest.first(), Some('!' | '^')) {
        out.push('^');
        i = 1;
    }
    let first = i;
    while i < rest.len() {
        let c = rest[i];
        if c == ']' && i > first {
            out.push(']');
            return Some((out, i + 1));
        }
        if c == '\\' && i + 1 < rest.len() {
            out.push_str(&class_char(rest[i + 1]));
            i += 2;
            continue;
        }
        let range = c == '-' && i > first && rest.get(i + 1).is_some_and(|next| *next != ']');
        if range {
            out.push('-');
        } else {
            out.push_str(&class_char(c));
        }
        i += 1;
    }
    None
}

fn class_char(c: char) -> String {
    if matches!(c, '\\' | '[' | ']' | '^' | '-' | '&' | '~') {
        format!("\\{c}")
    } else {
        c.to_string()
    }
}

#[cfg(test)]
#[path = "context_assistance_prompt_ignore_tests.rs"]
mod tests;
