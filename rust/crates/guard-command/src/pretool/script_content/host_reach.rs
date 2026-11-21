//! Programs fed on standard input that reach past the workspace.
//!
//! The workspace sandbox withholds the network and the home directory, but a
//! contained program still sees the rest of the host: it can list and read
//! system directories, enumerate and signal other processes, read the
//! clipboard or the screen, and rewrite the checkout's own Git configuration.
//! A Python program fed on standard input that asks for one of those things
//! is not one the sandbox makes safe, so it keeps its review instead of being
//! routed into containment. The screen reads the program's own source and
//! the local modules it imports:
//!
//! - imports of modules that observe or control other processes, the
//!   clipboard, the screen or the input devices (`psutil`, `pyperclip`,
//!   `PIL.ImageGrab`, `pynput`, `ctypes`, ...);
//! - calls that signal another process (`kill`, `killpg`, `pthread_kill`
//!   from `os` or `signal`, under any name they are imported as);
//! - code built at run time (`eval`, `exec`, `compile`, `__import__`, also
//!   through `builtins`, and `importlib.import_module`), which the scan
//!   cannot read;
//! - a string that names a path outside the workspace, on its own or as a
//!   word of a command line: an absolute path other than the shared temporary
//!   directory and the standard streams, the root directory, a relative path
//!   that climbs above where it starts, or a home-directory path;
//! - a string that names a path inside a `.git` directory, wherever it is;
//! - a command line, as one string or as an argument list, with a command
//!   that signals processes (`kill`, `pkill`, `killall`) or writes Git
//!   configuration (`git config` other than a read). Every command of a
//!   string counts, with shell quotes removed and after any leading
//!   redirections and reserved words (`if ...; then`). After a wrapper such
//!   as `env`, `sudo`, `taskset` or `sh -c`, and after `find -exec`, any
//!   later word may be the command, so an option value cannot hide it; `kill`
//!   with a process operand, `pkill` and `killall` count wherever they are.
//!
//! Strings are read as the value Python gives them, escapes decoded; one
//! whose value the scan cannot resolve keeps its review. Literals joined
//! with `+` or written next to each other are also read as the one string
//! they make. A formatted string is read with a field that is one string
//! constant standing for that string and any other field for an unknown
//! word, its expression scanned on its own. Fields that make one word
//! together are also read with every combination of the string constants
//! inside them, padded as their format spec pads them.
//!
//! Starting a program (`subprocess`, `os.system`) is not itself a reason to
//! hold: the program runs in the same sandbox, and the command line it is
//! given is read here like any other string.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

#[path = "host_reach_literals.rs"]
mod literals;
#[path = "host_reach_shell.rs"]
mod shell;

use super::system_files::lexical;
use super::{code_lines, Language};
use literals::{format_template, literal_value, spec_fill};
use shell::{command_reaches, git_config_reads, unquote};

const HOST_MODULES: &str = "psutil|pyperclip|pynput|pyautogui|mss|ctypes|PIL|keyboard|mouse|Xlib|Quartz|AppKit|win32api|win32gui|win32con|winreg";

/// An import statement of a module that observes or controls other
/// processes, the clipboard, the screen or the input devices. Only a
/// statement counts, at the start of a line or after `;` or `:`, so text that
/// merely mentions the import is not one.
static HOST_MODULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?m)(?:^|[;:])[ \t]*(?:from[ \t]+(?:{HOST_MODULES})\b|import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?[ \t]*,[ \t]*)*(?:{HOST_MODULES})\b)"
    ))
    .unwrap()
});

/// `from os import kill` and its siblings, including the parenthesized form
/// spread over several lines, which make the call bare.
static SIGNAL_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\bfrom\s+(?:os|signal)\s+import\s+",
        r"(?:\([^)]*\b(?:kill|killpg|pthread_kill)\b[^)]*\)",
        r"|[\w, \t\\]*\b(?:kill|killpg|pthread_kill)\b)",
    ))
    .unwrap()
});

/// `from os import *`, after which a bare `kill(` is the signal call.
static SIGNAL_STAR_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfrom\s+(?:os|signal)\s+import\s+\*").unwrap());

static BARE_SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[^.\w])(?:kill|killpg|pthread_kill)\s*\(").unwrap());

/// A signal call on a receiver; the receiver is checked against `os`,
/// `signal` and the names they are imported as.
static SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\w+)\s*\.\s*(?:kill|killpg|pthread_kill)\s*\(").unwrap());

/// The body of an `import` statement, to find `import os as proc`.
static IMPORT_STATEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[;:])[ \t]*import[ \t]+([^\n;#]+)").unwrap());

/// A call that runs code built at run time. `eval(` and its siblings count
/// as a bare name or through `builtins`, so a method such as
/// `pattern.compile(` or `cursor.execute(` does not.
static DYNAMIC_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?m)(?:(?:^|[^.\w]|\b(?:builtins|__builtins__)\s*\.\s*)",
        r"(?:eval|exec|__import__|compile)|\bimport_module)\s*\(",
    ))
    .unwrap()
});

/// A string literal with the word before its opening quote, which holds the
/// prefix (`r`, `b`, `f`, ...): triple-quoted across lines, or single-line
/// with backslash escapes, so `'it\'s'` is one literal.
static STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?s)(\w*)(?:"""(.*?)"""|'''(.*?)'''"#,
        r#"|"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')"#,
    ))
    .unwrap()
});

/// Calls that read or walk the path they are given first.
const PATH_CALLS: &[&str] = &[
    "listdir",
    "scandir",
    "walk",
    "chdir",
    "Path",
    "PurePath",
    "PosixPath",
    "glob",
    "iglob",
    "open",
    "join",
    "rmtree",
    "iterdir",
    "stat",
    "lstat",
    "exists",
    "isdir",
    "access",
];

/// The rest of an argument list for `git ... config`.
static GIT_CONFIG_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"["']git["']\s*,\s*(?:["'][^"'\n]*["']\s*,\s*)*?["']config["']"#,
        r#"((?:\s*,\s*["'][^"'\n]*["'])*)"#,
    ))
    .unwrap()
});

static QUOTED_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([^"'\n]*)["']"#).unwrap());

/// Absolute paths a contained program may name: the shared temporary
/// directory and the standard streams.
fn absolute_path_stays_local(path: &str) -> bool {
    let resolved = lexical(path);
    matches!(
        resolved.as_str(),
        "/tmp" | "/private/tmp" | "/dev/null" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr"
    ) || resolved.starts_with("/tmp/")
        || resolved.starts_with("/private/tmp/")
}

/// Whether a relative path climbs above the directory it starts from once
/// its `..` components are applied, as `..`, `../x` and `pkg/../..` do.
fn climbs_out(path: &str) -> bool {
    let mut depth = 0usize;
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return true,
            },
            _ => depth += 1,
        }
    }
    false
}

/// Whether one word of a string names a path outside the workspace or inside
/// a `.git` directory, the latter even under the temporary directory. A bare
/// `~name` counts only as the whole string, so prose such as `'~ approx'`
/// does not.
fn word_reaches(word: &str, alone: bool) -> bool {
    let word = unquote(word);
    let word = word.as_str();
    word.split(['/', '=']).any(|part| part == ".git")
        || word.split('=').any(|path| path_reaches(path, alone))
}

fn path_reaches(path: &str, alone: bool) -> bool {
    let mut chars = path.chars();
    let first = chars.next();
    let second = chars.next();
    if first == Some('/')
        && second.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return !absolute_path_stays_local(path);
    }
    if let Some(rest) = path.strip_prefix('~') {
        let name_end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'))
            .unwrap_or(rest.len());
        return rest[name_end..].starts_with('/') || (alone && name_end == rest.len());
    }
    path.contains("..") && climbs_out(path)
}

/// Whether one string value reaches past the workspace: through any shell
/// command in it that signals processes, writes Git configuration or lists
/// the root directory, or through any word that names an outside path.
fn literal_reaches(text: &str) -> bool {
    let alone = text.split_whitespace().count() == 1;
    text.split([';', '&', '|', '\n', '(', ')', '`', '{', '}'])
        .any(command_reaches)
        || text
            .split_whitespace()
            .any(|word| word_reaches(word, alone))
}

/// Whether the text before a literal ends in a call that reads or walks the
/// path it is given first, as in `os.listdir(`.
fn path_call_before(before: &str) -> bool {
    let Some(rest) = before.trim_end().strip_suffix('(') else {
        return false;
    };
    let rest = rest.trim_end();
    let name_start = rest
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_alphanumeric() || *c == '_')
        .last()
        .map_or(rest.len(), |(index, _)| index);
    PATH_CALLS.contains(&&rest[name_start..])
}

/// One string literal in the source: where it starts (its prefix
/// included) and ends, and its value, `None` when the scan cannot resolve
/// it.
struct Literal {
    start: usize,
    end: usize,
    value: Option<String>,
}

/// The value of a replacement field whose expression is one string constant,
/// with any `!r`, `:spec` or `=` after it, as in `{"/"}`.
fn constant_field(field: &str) -> Option<String> {
    let mut nested = false;
    let found = literals(field, &mut nested);
    let [only] = found.as_slice() else {
        return None;
    };
    let rest = field[only.end..].trim_start();
    let alone = field[..only.start].trim().is_empty()
        && (rest.is_empty() || rest.starts_with(['!', ':', '=']));
    alone.then(|| only.value.clone()).flatten()
}

/// The most readings of one word of a formatted string the scan tries
/// before it keeps the review instead.
const FIELD_READINGS: usize = 256;

/// The values one replacement field may take: the string it stands for (its
/// constant, or an unknown word), every string constant inside it, and each
/// constant padded on either side with every fill character the field's
/// format spec may name. An unknown word is never padded: it can already be
/// any path, and `{name:{width}}` must not read as one.
fn field_values(field: &str, reaches: &mut bool) -> Vec<String> {
    let mut nested = false;
    let constants = literals(field, &mut nested);
    *reaches |= nested || names_outside_path(field);
    let mut known: Vec<String> = constants
        .into_iter()
        .filter_map(|constant| constant.value)
        .collect();
    let padded: Vec<String> = spec_fill(field)
        .into_iter()
        .flat_map(|fill| {
            known
                .iter()
                .flat_map(move |value| [format!("{fill}{value}"), format!("{value}{fill}")])
        })
        .collect();
    known.extend(padded);
    let mut values = vec![constant_field(field).unwrap_or_else(|| "x".to_owned())];
    values.extend(known);
    values
}

/// The value of a formatted string. A field whose expression is one string
/// constant stands for that string; any other field stands for an unknown
/// word, with its expression scanned as code of its own. Fields written
/// next to each other with no white space between them make one word, and
/// that word is also read with its fields set to every combination of the
/// values they may take, so `f'{"." if a else ""}{"git"}/config'` is read as
/// `.git/config`. A word with more readings than the scan tries keeps the
/// review. `reaches` records what any reading finds.
fn formatted_value(body: &str, raw: bool, reaches: &mut bool) -> Option<String> {
    let (pieces, fields) = format_template(body)?;
    let pieces: Vec<String> = pieces
        .iter()
        .map(|piece| literal_value(piece, raw))
        .collect::<Option<_>>()?;
    let values: Vec<Vec<String>> = fields
        .iter()
        .map(|field| field_values(field, reaches))
        .collect();
    let fill = |choice: &[usize]| {
        let mut text = pieces[0].clone();
        for (index, piece) in pieces[1..].iter().enumerate() {
            text.push_str(&values[index][choice[index]]);
            text.push_str(piece);
        }
        text
    };
    let mut first = 0;
    while first < fields.len() {
        let mut end = first + 1;
        while end < fields.len() && !pieces[end].contains(char::is_whitespace) {
            end += 1;
        }
        let readings = values[first..end]
            .iter()
            .try_fold(1usize, |count, field| count.checked_mul(field.len()))
            .filter(|count| *count <= FIELD_READINGS);
        let Some(readings) = readings else {
            *reaches = true;
            return None;
        };
        let mut choice = vec![0; fields.len()];
        for mut reading in 0..readings {
            for (offset, field) in values[first..end].iter().enumerate() {
                choice[first + offset] = reading % field.len();
                reading /= field.len();
            }
            if literal_reaches(&fill(&choice)) {
                *reaches = true;
            }
        }
        first = end;
    }
    Some(fill(&vec![0; fields.len()]))
}

/// The string literals in `code`, read as the values Python gives them. A
/// formatted string's field expressions are scanned as code of their own;
/// `reaches` records one that reaches past the workspace.
fn literals(code: &str, reaches: &mut bool) -> Vec<Literal> {
    STRING
        .captures_iter(code)
        .filter_map(|captures| {
            let word = captures.get(1)?;
            let whole = captures.get(0)?;
            let body = captures.iter().skip(2).flatten().next()?;
            let prefix = word.len() <= 2 && word.as_str().chars().all(|c| "rbufRBUF".contains(c));
            let raw = prefix && word.as_str().contains(['r', 'R']);
            let formatted = prefix && word.as_str().contains(['f', 'F']);
            let value = if formatted {
                formatted_value(body.as_str(), raw, reaches)
            } else {
                literal_value(body.as_str(), raw)
            };
            Some(Literal {
                start: word.start(),
                end: whole.end(),
                value,
            })
        })
        .collect()
}

/// Whether the text between two literals joins them into one string:
/// nothing but white space, line continuations and at most one `+`.
fn joins(between: &str) -> bool {
    between
        .chars()
        .all(|c| c.is_whitespace() || c == '\\' || c == '+')
        && between.matches('+').count() <= 1
}

/// Whether any string literal in `code` reaches past the workspace, read as
/// the value Python gives it. A literal whose value the scan cannot resolve
/// counts, as does the root directory passed to a path call. Literals joined
/// with `+` or written next to each other are also read as the string they
/// make; when that string is itself added to something before it, a leading
/// `/` only separates it from that, so `base + '/' + 'sub'` stays relative.
fn names_outside_path(code: &str) -> bool {
    let mut reaches = false;
    let found = literals(code, &mut reaches);
    if reaches {
        return true;
    }
    let mut index = 0;
    while index < found.len() {
        let first = &found[index];
        let mut last = index;
        while found
            .get(last + 1)
            .is_some_and(|next| joins(&code[found[last].end..next.start]))
        {
            last += 1;
        }
        let chain = &found[index..=last];
        if chain.iter().any(|literal| literal.value.is_none()) {
            return true;
        }
        let values: Vec<&str> = chain
            .iter()
            .filter_map(|literal| literal.value.as_deref())
            .collect();
        let before = code[..first.start].trim_end();
        let alone_root =
            |value: &str, start: usize| value == "/" && path_call_before(code[..start].trim_end());
        if chain.iter().zip(&values).any(|(literal, value)| {
            alone_root(value, literal.start) || (*value != "/" && literal_reaches(value))
        }) {
            return true;
        }
        if chain.len() > 1 {
            let joined = values.concat();
            let joined = if before.ends_with('+') {
                joined.trim_start_matches('/')
            } else {
                joined.as_str()
            };
            if literal_reaches(joined) {
                return true;
            }
        }
        index = last + 1;
    }
    false
}

fn git_config_list_writes(code: &str) -> bool {
    GIT_CONFIG_LIST.captures_iter(code).any(|captures| {
        let words: Vec<&str> = QUOTED_WORD
            .captures_iter(&captures[1])
            .filter_map(|word| word.get(1).map(|word| word.as_str()))
            .collect();
        !git_config_reads(words)
    })
}

/// Names `os` and `signal` are reachable under: themselves and their
/// `import ... as` aliases.
fn signal_receivers(code: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::from(["os", "signal"]);
    for statement in IMPORT_STATEMENT.captures_iter(code) {
        let body = statement.get(1).map_or("", |body| body.as_str());
        for item in body.split(',') {
            let parts: Vec<&str> = item.split_whitespace().collect();
            if let [module, "as", alias] = parts.as_slice() {
                if matches!(*module, "os" | "signal") {
                    names.insert(alias);
                }
            }
        }
    }
    names
}

fn signals_processes(code: &str) -> bool {
    if SIGNAL_IMPORT.is_match(code)
        || (SIGNAL_STAR_IMPORT.is_match(code) && BARE_SIGNAL_CALL.is_match(code))
    {
        return true;
    }
    let receivers = signal_receivers(code);
    SIGNAL_CALL
        .captures_iter(code)
        .any(|call| receivers.contains(&call[1]))
}

/// Whether the Python `source` reaches past the workspace in a way the
/// sandbox does not take away.
pub(in crate::pretool) fn python_reaches_host(source: &str) -> bool {
    let code = code_lines(Language::Python, source);
    HOST_MODULE.is_match(&code)
        || signals_processes(&code)
        || DYNAMIC_CODE.is_match(&code)
        || git_config_list_writes(&code)
        || names_outside_path(&code)
}

#[cfg(test)]
#[path = "host_reach_tests.rs"]
mod tests;
