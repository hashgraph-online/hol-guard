//! `harness_diagnostics` op `shell_command`: an argument vector as one shell
//! command line, escaped for the shell it will run in.
//!
//! The request is `{"op": "shell_command", "command", "windows"}`. `command`
//! is the argument vector; `windows` is `true` for a Windows command line
//! (`subprocess.list2cmdline` rules, which the C runtime splits back into the
//! same arguments), `false` for a POSIX one (`shlex.join` rules), and `null`
//! for the platform this runtime runs on. The answer is `{"shell_command":
//! text}`.

use serde_json::{json, Value};

use crate::harness_diagnostics::{expect_keys, Fields};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn answer(fields: &Fields) -> KindResult {
    expect_keys(fields, &["op", "command", "windows"])?;
    let command = fields
        .get("command")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|part| part.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let windows = match fields.get("windows") {
        Some(Value::Null) => cfg!(windows),
        Some(Value::Bool(windows)) => *windows,
        _ => return Err(ERR_INVALID),
    };
    let line = if windows {
        windows_command_line(&command)
    } else {
        posix_command_line(&command)
    };
    Ok(json!({ "shell_command": line }))
}

/// The command line for the shell this runtime runs on, as `shell_command`
/// answers it with no `windows` choice.
pub(crate) fn platform_command_line(command: &[String]) -> String {
    let parts: Vec<&str> = command.iter().map(String::as_str).collect();
    if cfg!(windows) {
        windows_command_line(&parts)
    } else {
        posix_command_line(&parts)
    }
}

/// `shlex.join`: each argument quoted unless it is made only of characters
/// the shell never treats specially.
fn posix_command_line(command: &[&str]) -> String {
    command
        .iter()
        .map(|part| posix_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn posix_quote(part: &str) -> String {
    if part.is_empty() {
        return "''".to_owned();
    }
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if part.chars().all(safe) {
        return part.to_owned();
    }
    format!("'{}'", part.replace('\'', "'\"'\"'"))
}

/// `subprocess.list2cmdline`.
fn windows_command_line(command: &[&str]) -> String {
    let mut line = String::new();
    for (index, part) in command.iter().enumerate() {
        if index > 0 {
            line.push(' ');
        }
        let quoted = part.is_empty() || part.contains(' ') || part.contains('\t');
        if quoted {
            line.push('"');
        }
        let mut backslashes = 0usize;
        for c in part.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    line.push_str(&"\\".repeat(backslashes * 2));
                    backslashes = 0;
                    line.push_str("\\\"");
                }
                _ => {
                    line.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    line.push(c);
                }
            }
        }
        line.push_str(&"\\".repeat(backslashes));
        if quoted {
            line.push_str(&"\\".repeat(backslashes));
            line.push('"');
        }
    }
    line
}

#[cfg(test)]
#[path = "harness_shell_command_tests.rs"]
mod tests;
