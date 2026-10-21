//! The programs a script's `#!` line asks the kernel to run.
use super::*;
use std::collections::VecDeque;

/// Shebang lines longer than this are not read; they count as unclear.
const SHEBANG_BYTES: usize = 256;

/// What a script's first line says it runs.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Shebang {
    /// No `#!` line, or one this does not read: the script is not held to an
    /// interpreter.
    Absent,
    /// Every program the line starts, in order: the interpreter, then for
    /// `env` the program it looks up.
    Runs(Vec<String>),
    /// A line whose program cannot be named with confidence.
    Unclear,
}

/// Read the `#!` line of `script`.
pub(super) fn shebang(script: &Path) -> Shebang {
    let mut head = [0_u8; SHEBANG_BYTES];
    let Some(read) = std::fs::File::open(script)
        .ok()
        .and_then(|mut file| file.read(&mut head).ok())
    else {
        return Shebang::Absent;
    };
    let Some(line) = head[..read].strip_prefix(b"#!") else {
        return Shebang::Absent;
    };
    // A line the buffer cuts off may still start its interpreter, so it is
    // neither read as a shorter line nor taken for a script with none.
    let end = match line.iter().position(|byte| *byte == b'\n') {
        Some(end) => end,
        None if read < SHEBANG_BYTES => line.len(),
        None => return Shebang::Unclear,
    };
    match std::str::from_utf8(&line[..end]) {
        Ok(text) => runs(text),
        Err(_) => Shebang::Unclear,
    }
}

fn runs(line: &str) -> Shebang {
    let mut words = line.split_ascii_whitespace();
    let Some(first) = words.next() else {
        return Shebang::Absent;
    };
    let mut programs = vec![first.to_owned()];
    if Path::new(first).file_name().and_then(OsStr::to_str) == Some("env") {
        // The `env` named on the line is itself launched, wherever it is.
        match env_program(words) {
            Ok(Some(program)) => programs.push(program),
            Ok(None) => {}
            Err(()) => return Shebang::Unclear,
        }
    }
    Shebang::Runs(programs)
}

/// The program `env` looks up from its operands: the first word that is not
/// an option, the operand an option consumes or an assignment. `Err` for
/// anything that could move the lookup or that this does not parse.
fn env_program<'a>(words: impl Iterator<Item = &'a str>) -> Result<Option<String>, ()> {
    let mut queue: VecDeque<String> = words.map(str::to_owned).collect();
    let mut options = true;
    while let Some(word) = queue.pop_front() {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with('-') && word.len() > 1 {
            env_option(&word, &mut queue)?;
        } else if !word.contains('=') {
            return Ok(Some(word));
        }
    }
    Ok(None)
}

/// Take one `env` option word and the operand it consumes off `queue`. A
/// split-string option replaces the rest of the queue with its operands.
fn env_option(word: &str, queue: &mut VecDeque<String>) -> Result<(), ()> {
    if let Some(long) = word.strip_prefix("--") {
        let (name, attached) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (long, None),
        };
        return match name {
            "split-string" => split_string(attached.or_else(|| queue.pop_front()), queue),
            "unset" | "argv0" => {
                if attached.is_none() {
                    queue.pop_front();
                }
                Ok(())
            }
            // These move where the program is looked up from.
            "chdir" => Err(()),
            _ => Ok(()),
        };
    }
    let flags = &word[1..];
    for (offset, flag) in flags.char_indices() {
        let rest = &flags[offset + flag.len_utf8()..];
        match flag {
            'S' => {
                let text = (!rest.is_empty())
                    .then(|| rest.to_owned())
                    .or_else(|| queue.pop_front());
                return split_string(text, queue);
            }
            'u' | 'a' => {
                if rest.is_empty() {
                    queue.pop_front();
                }
                return Ok(());
            }
            'C' | 'P' => return Err(()),
            _ => {}
        }
    }
    Ok(())
}

/// Replace `queue` with the operands `text` and the words after it split into.
fn split_string(text: Option<String>, queue: &mut VecDeque<String>) -> Result<(), ()> {
    let mut joined = text.ok_or(())?;
    for word in queue.drain(..) {
        joined.push(' ');
        joined.push_str(&word);
    }
    queue.extend(split_words(&joined)?);
    Ok(())
}

/// Split on whitespace outside single and double quotes. Anything that would
/// expand or escape, or a quote left open, is not parsed.
fn split_words(text: &str) -> Result<Vec<String>, ()> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        match character {
            quote @ ('\'' | '"') => {
                started = true;
                loop {
                    match chars.next() {
                        Some(closing) if closing == quote => break,
                        Some('\\') if quote == '"' => return Err(()),
                        Some('$') if quote == '"' => return Err(()),
                        Some(inner) => current.push(inner),
                        None => return Err(()),
                    }
                }
            }
            '\\' | '$' => return Err(()),
            // A word that opens with `#` starts a comment.
            '#' if !started => break,
            space if space.is_ascii_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            other => {
                started = true;
                current.push(other);
            }
        }
    }
    if started {
        words.push(current);
    }
    Ok(words)
}

#[cfg(test)]
#[path = "launch_shebang_tests.rs"]
mod tests;
