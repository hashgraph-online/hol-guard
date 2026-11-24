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

/// Whether `model`, a whole command that `words` were taken from, is a chain
/// of plain readers naming a dotenv template, so a credential-word screen may
/// set aside a template word that the tracked-template proof accepts.
pub(crate) fn names_template_reads(
    model: &crate::CanonicalCommandV1,
    words: &[&String],
    cwd: Option<&str>,
) -> bool {
    model.wrapper_chain.is_empty()
        && words.iter().any(|word| template_named(word))
        && chain_reads_only(&model.normalized_text, cwd.map(Path::new), None)
}

/// The name a projected read gives a committed template in place of its own.
const STAND_IN: &str = "hol-guard-committed-template";

/// `command` with each committed dotenv template it only reads renamed to a
/// plain sibling name, so the read proofs judge the rest of the command.
///
/// Every word naming a template must pass the tracked-template proof, and the
/// projected text must parse to the same words with only those renamed, so a
/// word that merely contains a template name is never rewritten.
pub(crate) fn project(command: &str, cwd: Option<&str>) -> Option<String> {
    let parse = |text: &str| {
        parse_shell_command(
            text,
            cwd.map(Path::new),
            None,
            "posix",
            "shell_string",
            "guard-shell",
            false,
        )
    };
    if !chain_reads_only(command, cwd.map(Path::new), None) {
        return None;
    }
    // Every word the rename can touch is proven and compared: the arguments
    // and the redirect targets, which the model keeps apart from them.
    let words = |text: &str| -> Vec<String> {
        let model = parse(text);
        model
            .segments
            .iter()
            .flat_map(|segment| segment.arguments.clone())
            .chain(model.redirects.iter().map(|redirect| redirect.target.clone()))
            .collect()
    };
    let original = words(command);
    let templates: Vec<&String> = original
        .iter()
        .filter(|word| template_named(word))
        .collect();
    if templates.is_empty()
        || !templates
            .iter()
            .all(|word| crate::pretool::proven_tracked_dotenv_template(word, cwd))
    {
        return None;
    }
    let renamed = |word: &str| match word.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/{STAND_IN}"),
        None => STAND_IN.to_owned(),
    };
    let mut projected = command.to_owned();
    for template in &templates {
        projected = projected.replace(template.as_str(), &renamed(template));
    }
    let expected: Vec<String> = original
        .iter()
        .map(|word| {
            if template_named(word) {
                renamed(word)
            } else {
                word.clone()
            }
        })
        .collect();
    (words(&projected) == expected && chain_reads_only(&projected, cwd.map(Path::new), None))
        .then_some(projected)
}

/// Whether every command in `command_text` is a reader from `READERS` whose
/// output reaches only a pipe, the terminal or `/dev/null`.
pub(crate) fn chain_reads_only(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
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
    // A process substitution runs a command the model keeps inside a word.
    model.uncertainty_reason.is_none()
        && !command_text.contains("<(")
        && !command_text.contains(">(")
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
                // `printf -v` assigns a variable and `%n` stores a count in one.
                && !(segment.executable.as_deref() == Some("printf")
                    && segment
                        .arguments
                        .iter()
                        .any(|argument| argument.starts_with("-v") || argument.contains("%n")))
                && !(segment.executable.as_deref() == Some("rg")
                    && segment.arguments.iter().any(|argument| {
                        argument.starts_with("--pre")
                            || argument.starts_with("--hostname-bin")
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
                "<" => !redirect.target.starts_with('('),
                _ => false,
            }
        })
}

#[cfg(test)]
#[path = "shell_template_reads_tests.rs"]
mod tests;
