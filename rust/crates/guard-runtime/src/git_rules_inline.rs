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

pub(crate) fn process_calls(code: &str) -> Vec<Call> {
    let mut calls = Vec::new();
    if code.len() > MAX_CODE {
        return calls;
    }
    let bytes = code.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' || byte == b'\'' || byte == b'`' {
            // Skip string literals so a name inside one is not a call.
            index = literal(code, index).map_or(bytes.len(), |(_, end)| end);
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
        if !PROCESS_CALLS.contains(&name) {
            continue;
        }
        let open = skip_space(code, index);
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        if let Some(call) = first_argument(code, skip_space(code, open + 1)) {
            calls.push(call);
        }
    }
    calls
}

fn first_argument(code: &str, at: usize) -> Option<Call> {
    // `spawn("git", ["add", "."])` names the program, then its arguments.
    if let Some(call) = program_and_list(code, at) {
        return Some(call);
    }
    match code.as_bytes().get(at)? {
        b'"' | b'\'' | b'`' => literal(code, at).map(|(text, _)| Call::Shell(text)),
        b'[' => list(code, at + 1, b']').map(Call::Argv),
        _ => None,
    }
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
            b'"' | b'\'' | b'`' => {
                let (text, end) = literal(code, at)?;
                words.push(text);
                at = end;
            }
            _ => {
                // A name or expression: its value is unknown.
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
    let quote = *bytes.get(at)?;
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
