//! Process calls inside inline Python or JavaScript (`python3 -c`,
//! `node -e`). Only the first argument of a call that starts a process is
//! read, so a git command in a `print` or `console.log` is never a match.

/// What a process call runs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Call {
    /// A string handed to a shell (`os.system("git add .")`).
    Shell(String),
    /// An argument list (`subprocess.run(["git", "add", "."])`). A word that
    /// is not a literal is kept as `$VAR`.
    Argv(Vec<String>),
}

/// A process call and the folder it starts in, when it names one: the
/// literal `cwd`, or `$VAR` for a value Guard cannot read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Found {
    pub(crate) call: Call,
    pub(crate) cwd: Option<String>,
}

/// Calls that start a process with their first argument.
const PROCESS_CALLS: &[&str] = &[
    "system",
    "popen",
    "run",
    "call",
    "check_call",
    "check_output",
    "Popen",
    "getoutput",
    "getstatusoutput",
    "execSync",
    "exec",
    "spawnSync",
    "spawn",
    "execFileSync",
    "execFile",
];

/// Inline code longer than this is not read.
const MAX_CODE: usize = 16_384;

/// How deep template expressions inside template expressions are read.
const MAX_NESTING: usize = 8;

/// The process calls in `code`, or `None` when the code is too long to
/// read. `hash_comments` says the language starts a line comment with `#`
/// (Python, Ruby, Perl); otherwise `//` and `/* */` are comments
/// (JavaScript).
pub(crate) fn scan(code: &str, hash_comments: bool) -> Option<Vec<Found>> {
    if code.len() > MAX_CODE {
        return None;
    }
    let mut calls = Vec::new();
    calls_in(code, hash_comments, 0, &mut calls);
    Some(calls)
}

/// The calls alone, for tests.
#[cfg(test)]
pub(crate) fn process_calls(code: &str, hash_comments: bool) -> Vec<Call> {
    scan(code, hash_comments)
        .unwrap_or_default()
        .into_iter()
        .map(|found| found.call)
        .collect()
}

/// What code too long to read may do to git, from the words in it: skip
/// the hooks, and stage the whole tree.
pub(crate) fn unread_risks(code: &str) -> (bool, bool) {
    if !code.contains("git") {
        return (false, false);
    }
    let hooks = [
        "--no-verify",
        "hooksPath",
        "HUSKY",
        "LEFTHOOK",
        "SKIP=",
        "OVERCOMMIT_DISABLE",
    ]
    .iter()
    .any(|word| code.contains(word));
    // Every spelling of a whole-tree stage: `git-stage(1)` is Git's own second
    // name for `git-add(1)`, and `-- .` spells the dot as a pathspec rather
    // than an option. A bare `--all` already covers both names.
    let stage = [
        "add -A",
        "add .",
        "add -u",
        "add -- .",
        "stage -A",
        "stage .",
        "stage -u",
        "stage -- .",
        "\"-A\"",
        "'-A'",
        "--all",
        "commit -a",
    ]
    .iter()
    .any(|word| code.contains(word));
    (hooks, stage)
}

fn calls_in(code: &str, hash_comments: bool, nesting: usize, calls: &mut Vec<Found>) {
    let bytes = code.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'`' && hash_comments {
            // Ruby and Perl run a backtick string as a shell command.
            match literal(code, index) {
                Some((text, end)) => {
                    calls.push(Found {
                        call: Call::Shell(text),
                        cwd: None,
                    });
                    index = end;
                }
                None => index = bytes.len(),
            }
            continue;
        }
        if byte == b'`' {
            // A JavaScript template runs the expressions in its `${...}`.
            let (expressions, end) = template(code, index);
            if nesting < MAX_NESTING {
                for expression in expressions {
                    calls_in(expression, hash_comments, nesting + 1, calls);
                }
            }
            index = end;
            continue;
        }
        if byte == b'"' || byte == b'\'' {
            // Skip string literals so a name inside one is not a call.
            index = literal(code, index).map_or(bytes.len(), |(_, end)| end);
            continue;
        }
        // Skip comments, which run nothing. A `#` starts one only at the
        // start of a word: Perl's `$#array` and `s#a#b#` are code.
        let next = bytes.get(index + 1).copied();
        let word_start = index
            .checked_sub(1)
            .is_none_or(|at| bytes[at].is_ascii_whitespace() || bytes[at] == b';');
        if (hash_comments && byte == b'#' && word_start)
            || (!hash_comments && byte == b'/' && next == Some(b'/'))
        {
            index = code[index..]
                .find('\n')
                .map_or(bytes.len(), |end| index + end);
            continue;
        }
        if !hash_comments && byte == b'/' && next == Some(b'*') {
            index = code[index + 2..]
                .find("*/")
                .map_or(bytes.len(), |end| index + 2 + end + 2);
            continue;
        }
        if !is_word(byte) || (index > 0 && is_word(bytes[index - 1])) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_word(bytes[index]) {
            index += 1;
        }
        let name = &code[start..index];
        if !PROCESS_CALLS.contains(&name) || defined_here(code, start, name) {
            continue;
        }
        let open = skip_space(code, index);
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        if let Some(call) = first_argument(code, skip_space(code, open + 1)) {
            let cwd = closing(code, open).and_then(|close| cwd(&code[open + 1..close]));
            calls.push(Found { call, cwd });
        }
    }
}

/// The `${...}` expressions of the template literal at `at`, and the index
/// past its closing backtick.
fn template(code: &str, at: usize) -> (Vec<&str>, usize) {
    let bytes = code.as_bytes();
    let mut expressions = Vec::new();
    let mut index = at + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'`' => return (expressions, index + 1),
            b'$' if bytes.get(index + 1) == Some(&b'{') => {
                let start = index + 2;
                let mut depth = 1usize;
                let mut end = start;
                while end < bytes.len() {
                    match bytes[end] {
                        // A brace inside a string or template is text.
                        b'"' | b'\'' => {
                            end = literal(code, end).map_or(bytes.len(), |(_, next)| next);
                            continue;
                        }
                        b'`' => {
                            end = template(code, end).1;
                            continue;
                        }
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    end += 1;
                }
                expressions.push(&code[start..end.min(bytes.len())]);
                index = end + 1;
            }
            _ => index += 1,
        }
    }
    (expressions, bytes.len())
}

fn first_argument(code: &str, at: usize) -> Option<Call> {
    // `spawn("git", ["add", "."])` names the program, then its arguments.
    if let Some(call) = program_and_list(code, at) {
        return Some(call);
    }
    match code.as_bytes().get(at)? {
        b'"' | b'\'' | b'`' => joined(code, at).map(Call::Shell),
        b'[' => list(code, at + 1, b']').map(Call::Argv),
        _ => None,
    }
}

/// A literal and the literals joined to it with `+`. A part that is not a
/// literal is kept as `$VAR`.
fn joined(code: &str, at: usize) -> Option<String> {
    let (mut text, mut end) = literal(code, at)?;
    let bytes = code.as_bytes();
    loop {
        let plus = skip_space(code, end);
        if bytes.get(plus) != Some(&b'+') {
            return Some(text);
        }
        let next = skip_space(code, plus + 1);
        match literal(code, next) {
            Some((part, after)) => {
                text.push_str(&part);
                end = after;
            }
            None => {
                text.push_str("$VAR");
                return Some(text);
            }
        }
    }
}

/// The index of the `)` that closes the `(` at `open`.
fn closing(code: &str, open: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' | b'`' => {
                index = literal(code, index)?.1;
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// The folder a call's arguments start it in: `cwd="src"` or `{cwd: "src"}`.
fn cwd(arguments: &str) -> Option<String> {
    let bytes = arguments.as_bytes();
    let mut from = 0;
    while let Some(found) = arguments[from..].find("cwd") {
        let start = from + found;
        from = start + 3;
        if start > 0 && is_word(bytes[start - 1]) || bytes.get(from).is_some_and(|b| is_word(*b)) {
            continue;
        }
        let sign = skip_space(arguments, from);
        if !matches!(bytes.get(sign), Some(b'=' | b':')) || bytes.get(sign + 1) == Some(&b'=') {
            continue;
        }
        let value = skip_space(arguments, sign + 1);
        return Some(
            literal(arguments, value)
                .filter(|(_, end)| {
                    matches!(
                        bytes.get(skip_space(arguments, *end)),
                        None | Some(b',' | b'}' | b')')
                    )
                })
                .map_or_else(|| "$VAR".to_owned(), |(text, _)| text),
        );
    }
    None
}

/// `"git", ["add", "."]`: a program literal followed by its argument list.
fn program_and_list(code: &str, at: usize) -> Option<Call> {
    let (program, end) = literal(code, at)?;
    let comma = skip_space(code, end);
    if code.as_bytes().get(comma) != Some(&b',') {
        return None;
    }
    let open = skip_space(code, comma + 1);
    if code.as_bytes().get(open) != Some(&b'[') {
        return None;
    }
    let mut words = vec![program];
    words.extend(list(code, open + 1, b']')?);
    Some(Call::Argv(words))
}

/// The elements of a list literal from `at` up to `close`.
fn list(code: &str, mut at: usize, close: u8) -> Option<Vec<String>> {
    let bytes = code.as_bytes();
    let mut words = Vec::new();
    loop {
        at = skip_space(code, at);
        match bytes.get(at)? {
            byte if *byte == close => return Some(words),
            b',' => at += 1,
            b'"' | b'\'' | b'`'
                if literal(code, at).is_some_and(|(_, end)| {
                    let next = bytes.get(skip_space(code, end));
                    next == Some(&b',') || next == Some(&close)
                }) =>
            {
                let (text, end) = literal(code, at)?;
                words.push(text);
                at = end;
            }
            _ => {
                // A name or expression, or a literal joined to one
                // (`"." + "/docs"`): its value is unknown.
                let mut depth = 0usize;
                while let Some(byte) = bytes.get(at) {
                    match byte {
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' if depth > 0 => depth -= 1,
                        b',' if depth == 0 => break,
                        byte if *byte == close && depth == 0 => break,
                        _ => {}
                    }
                    at += 1;
                }
                words.push("$VAR".into());
            }
        }
    }
}

/// A quoted literal starting at `at`: its text and the index past it.
/// Python prefixes (`f"..."`, `r"..."`) are read as the quote that follows.
fn literal(code: &str, at: usize) -> Option<(String, usize)> {
    let bytes = code.as_bytes();
    let quote = *bytes
        .get(at)
        .filter(|byte| matches!(byte, b'"' | b'\'' | b'`'))?;
    let triple = bytes.get(at + 1) == Some(&quote) && bytes.get(at + 2) == Some(&quote);
    let mut index = at + if triple { 3 } else { 1 };
    let mut text = String::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            if let Some(next) = code[index + 1..].chars().next() {
                text.push(match next {
                    'n' => '\n',
                    't' => '\t',
                    other => other,
                });
                index += 1 + next.len_utf8();
                continue;
            }
            return None;
        }
        if byte == quote
            && (!triple
                || (bytes.get(index + 1) == Some(&quote) && bytes.get(index + 2) == Some(&quote)))
        {
            return Some((text, index + if triple { 3 } else { 1 }));
        }
        let character = code[index..].chars().next()?;
        text.push(character);
        index += character.len_utf8();
    }
    None
}

/// Whether a bare `name(...)` at `at` calls a function the code defines
/// itself (`def run(...)`, `function run(...)`, `run = lambda ...`,
/// `const run = (...) => ...`) rather than a process API. A method call
/// (`subprocess.run`) is always a process call, and so is a local function
/// in code that reaches a process module at all, since it may wrap one. A
/// name assigned anything but a function (`system = o.system`) may be a
/// process API under another name, so it is not a local definition.
fn defined_here(code: &str, at: usize, name: &str) -> bool {
    if at > 0 && code.as_bytes()[at - 1] == b'.' {
        return false;
    }
    if PROCESS_MODULES.iter().any(|module| code.contains(module)) {
        return false;
    }
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(found) = code[from..].find(name) {
        let start = from + found;
        let end = start + name.len();
        from = end;
        if (start > 0 && is_word(bytes[start - 1])) || bytes.get(end).is_some_and(|b| is_word(*b)) {
            continue;
        }
        let before = code[..start].trim_end();
        let declared = ["def", "function"].iter().any(|keyword| {
            before.strip_suffix(keyword).is_some_and(|rest| {
                !rest.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            })
        });
        let after = code[end..].trim_start();
        let assigned_function = after
            .strip_prefix('=')
            .filter(|value| !value.starts_with('='))
            .is_some_and(function_value);
        if declared || assigned_function {
            return true;
        }
    }
    false
}

/// Whether an assigned value is a function written here: a `lambda`, a
/// `function` expression or an arrow function.
fn function_value(value: &str) -> bool {
    let value = value.trim_start();
    let statement = value.split(['\n', ';']).next().unwrap_or(value);
    ["lambda", "function", "async"].iter().any(|keyword| {
        value
            .strip_prefix(keyword)
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
    }) || statement.split_once("=>").is_some_and(|(head, _)| {
        let head = head.trim();
        head.starts_with('(') || (!head.is_empty() && head.bytes().all(is_word))
    })
}

/// Names that reach a process API, so a local function may wrap one.
const PROCESS_MODULES: &[&str] = &[
    "subprocess",
    "os.",
    "import os",
    "from os",
    "importlib",
    "child_process",
    "commands",
    "pty",
    "Deno.",
    "Bun.",
    "shelljs",
    "execa",
    "import(",
    "require(",
    "__import__",
    "getattr",
];

fn skip_space(code: &str, mut at: usize) -> usize {
    let bytes = code.as_bytes();
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
