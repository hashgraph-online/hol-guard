//! A shell read of a committed dotenv template such as `.env.example`.
//!
//! The secret-read screen matches the dotenv family by name, so `grep -n PORT
//! .env.example` reviews as a read of the local `.env` it documents. The read
//! tool already opens such a template once the repository's index lists it
//! and the secret scan finds no live value in it
//! (`proven_tracked_dotenv_template`). A shell read gets the same relief, but
//! only when nothing in the command could change the file between the proof
//! and the read, or use it as anything but text to print:
//!
//! - every command is a plain reader or a print (`cat`, `head`, `tail`,
//!   `grep`, `rg`, `wc`, `nl`, `cut`, `echo`, `printf`), so no step writes,
//!   moves, links or checks out the template first;
//! - no command substitution, heredoc, wrapper, environment prefix or
//!   overridden `PATH`;
//! - output goes only to the pipe, the terminal or `/dev/null`;
//! - `rg` runs no preprocessor or decompressor.
//!
//! Every other dotenv file, an untracked template and a template holding a
//! value keep the review.

use std::path::Path;

use crate::command_model::parse_shell_command;

/// Programs that only read their operands and print.
const READERS: &[&str] = &[
    "cat", "cut", "echo", "egrep", "fgrep", "grep", "head", "nl", "printf", "rg", "tail", "wc",
];

/// Drops from `sensitive` every committed dotenv template the command only
/// reads.
pub(crate) fn relieve_template_reads(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    sensitive: &mut Vec<String>,
) {
    if !sensitive.iter().any(|path| template_named(path))
        || !chain_reads_only(command_text, cwd, home_dir)
    {
        return;
    }
    let cwd = cwd.and_then(Path::to_str);
    sensitive.retain(|path| {
        !(template_named(path) && crate::pretool::proven_tracked_dotenv_template(path, cwd))
    });
}

fn template_named(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(guard_secure_fs::dotenv_template_basename)
}

/// Whether every command in `command_text` is a reader from `READERS` whose
/// output reaches only a pipe, the terminal or `/dev/null`.
fn chain_reads_only(command_text: &str, cwd: Option<&Path>, home_dir: Option<&Path>) -> bool {
    if command_text.trim().is_empty() {
        return false;
    }
    let model = parse_shell_command(
        command_text,
        cwd,
        home_dir,
        "posix",
        "shell_string",
        "guard-shell",
        false,
    );
    model.uncertainty_reason.is_none()
        && model.embedded_commands.is_empty()
        && model.wrapper_chain.is_empty()
        && !model.segments.is_empty()
        && model.segments.iter().all(|segment| {
            segment.wrapper_chain.is_empty()
                && !segment.path_overridden
                && segment.environment_names.is_empty()
                && segment.execution_context.starts_with("top:")
                && segment
                    .executable
                    .as_deref()
                    .is_some_and(|program| READERS.contains(&program))
                && !(segment.executable.as_deref() == Some("rg")
                    && segment.arguments.iter().any(|argument| {
                        argument.starts_with("--pre")
                            || argument == "--search-zip"
                            || (argument.starts_with('-')
                                && !argument.starts_with("--")
                                && argument.contains('z'))
                    }))
        })
        && model.redirects.iter().all(|redirect| {
            let operator = redirect
                .operator
                .trim_start_matches(|c: char| c.is_ascii_digit());
            match operator {
                ">" | ">>" | ">|" | "&>" | "&>>" => redirect.target == "/dev/null",
                ">&" => redirect.target.chars().all(|c| c.is_ascii_digit()),
                "<" => true,
                _ => false,
            }
        })
}

#[cfg(test)]
#[path = "shell_template_reads_tests.rs"]
mod tests;
