//! The `#!` interpreter of a launcher script, for `runtime-identity-probe`.
//!
//! Only the first bytes of a regular file are read. A FIFO or device is never
//! opened blocking and never read, and an `env` line is understood only when
//! its options are known, so an interpreter is never guessed.

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::runtime_identity_probe::open_read_only;

const SHEBANG_BYTES: u64 = 256;
const SHEBANG_NAME_LIMIT: usize = 64;
/// `env` options that take no value.
const ENV_FLAGS: [&str; 9] = [
    "-i",
    "-",
    "-0",
    "-v",
    "-S",
    "--ignore-environment",
    "--null",
    "--debug",
    "--split-string",
];
/// `env` options whose value is the next token.
const ENV_VALUE_OPTIONS: [&str; 5] = ["-u", "-C", "-P", "--unset", "--chdir"];

/// The interpreter a script's first line names, one level deep. `lookup`
/// resolves a bare `env` program name through the launch's search path.
pub(crate) fn shebang_interpreter(
    path: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let head = read_head(Path::new(path))?;
    let line = head.strip_prefix(b"#!")?;
    let line = line.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let program = *tokens.first()?;
    if Path::new(program)
        .file_name()
        .is_some_and(|name| name == "env")
    {
        return env_command(&tokens[1..]).and_then(lookup);
    }
    let candidate = Path::new(program);
    (candidate.is_absolute() && fs::metadata(candidate).is_ok_and(|meta| meta.is_file()))
        .then(|| program.to_owned())
}

/// The first bytes of a regular file. The path is checked, then the opened
/// file is checked again, since the path may have been swapped in between.
fn read_head(path: &Path) -> Option<Vec<u8>> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = open_read_only(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut head = Vec::with_capacity(SHEBANG_BYTES as usize);
    file.take(SHEBANG_BYTES).read_to_end(&mut head).ok()?;
    Some(head)
}

/// The program an `env` shebang launches, or `None` when its options are not understood.
pub(crate) fn env_command<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if token == "--" {
            index += 1;
            break;
        }
        if ENV_VALUE_OPTIONS.contains(&token) {
            index += 2;
        } else if ENV_FLAGS.contains(&token)
            || (token.starts_with("--") && token.contains('='))
            || ["-u", "-C", "-P"]
                .iter()
                .any(|prefix| token.starts_with(prefix))
        {
            index += 1;
        } else if token.starts_with('-') {
            return None;
        } else if token.contains('=') {
            index += 1;
        } else {
            break;
        }
    }
    let program = *tokens.get(index)?;
    let quoted = program.starts_with(['\'', '"']);
    (program.chars().count() <= SHEBANG_NAME_LIMIT && !quoted).then_some(program)
}

#[cfg(test)]
#[path = "runtime_identity_launch_shebang_tests.rs"]
mod tests;
