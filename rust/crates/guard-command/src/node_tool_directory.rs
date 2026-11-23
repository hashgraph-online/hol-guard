//! The directory a package runner names for the run it starts.
//!
//! `bunx --cwd packages/app tsc --noEmit` is a `tsc` run in that project, and
//! the admission and the sink have to read the directory the same way or the
//! sink plans a run the receipt does not describe. One reading answers for
//! both: a relative directory is carried as written, an absolute one is
//! carried as the remainder below the directory the command was made from, and
//! anything else stops the peel.

#[cfg(test)]
#[path = "node_tool_directory_tests.rs"]
mod tests;

use std::path::{Component, Path};

/// A lexical subdirectory of the directory the run was called from.
///
/// The sink resolves it and refuses an escape, so this only has to reject
/// the spellings that are not a subdirectory at all: an option, an absolute
/// or home-relative path, a shell expansion, and a parent step.
///
/// A Windows drive prefix is one of those spellings. `C:/repo/other` has no
/// leading separator, so nothing above would read it as absolute, yet
/// Windows resolves it from that drive's root rather than from the command's
/// own directory, and `C:other` resolves from whatever directory the process
/// last held on that drive. Neither is a subdirectory of anything this route
/// can name, so both stop here.
pub(crate) fn workspace_relative(directory: &str) -> bool {
    !directory.is_empty()
        && !directory.starts_with(['-', '/', '~', '$'])
        && !directory.contains(['\\', '$', '`'])
        && !drive_prefixed(directory)
        && directory
            .trim_end_matches('/')
            .split('/')
            .all(|part| !part.is_empty() && part != "..")
}

/// Whether the word opens with a Windows drive letter, with or without a
/// separator after it.
fn drive_prefixed(directory: &str) -> bool {
    let bytes = directory.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// A directory a runner named for the run, read as the run will spell it.
///
/// Bun accepts an absolute `--cwd` as readily as a relative one, and a command
/// written from a project root usually spells it absolutely. Both name the same
/// place, so both are read here: a relative directory is carried as written, and
/// an absolute one is carried as the remainder below the directory the command
/// was made from. An absolute directory that *is* that directory names no
/// subdirectory, so it carries none and the run stands where it already stood.
///
/// `None` means the word names no directory this route reads — it is outside
/// the command's own directory, it climbs out of it, or the shell would have
/// rewritten it. The peel then stops, the word stands where a tool name is
/// read, no supported tool answers to it, and the command keeps its ordinary
/// review.
pub(crate) fn named_run_directory(named: &str, base: Option<&Path>) -> Option<Option<String>> {
    if named.is_empty()
        || named.contains(['\\', '$', '`'])
        || named.starts_with(['-', '~'])
        || drive_prefixed(named)
    {
        return None;
    }
    if !named.starts_with('/') {
        return workspace_relative(named).then(|| Some(named.trim_end_matches('/').to_owned()));
    }
    let relative = Path::new(named).strip_prefix(base?).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        parts.push(part.to_str()?.to_owned());
    }
    Some((!parts.is_empty()).then(|| parts.join("/")))
}

/// The options a local-bin runner reads for itself, peeled off the words
/// ahead of the tool's own name.
///
/// `--no-install` only refuses to fetch what is missing. `--cwd` is Bun's
/// own option, so `bunx --cwd packages/app tsc --noEmit` is the `tsc` run
/// that project spells, started in that project. npm has no such option, so
/// only Bun's spelling peels one. The admission and the sink peel here
/// together, which is what keeps the run the admission proved and the run
/// the sink starts the same run, in the same directory.
///
/// A second `--cwd`, or one naming anything but a directory at or below the
/// one the command was made from, stops the peel.
pub(crate) fn runner_options_peeled<'a>(
    runner: &str,
    arguments: &'a [String],
    base: Option<&Path>,
) -> (Option<String>, &'a [String]) {
    let mut directory: Option<String> = None;
    let mut named_once = false;
    let mut rest = arguments;
    loop {
        rest = match rest {
            [flag, tail @ ..] if flag == "--no-install" => tail,
            [flag, named, tail @ ..] if runner == "bunx" && flag == "--cwd" && !named_once => {
                let Some(named) = named_run_directory(named, base) else {
                    return (directory, rest);
                };
                named_once = true;
                directory = named;
                tail
            }
            [flag, tail @ ..] if runner == "bunx" && !named_once && flag.starts_with("--cwd=") => {
                let Some(named) = named_run_directory(&flag["--cwd=".len()..], base) else {
                    return (directory, rest);
                };
                named_once = true;
                directory = named;
                tail
            }
            _ => return (directory, rest),
        };
    }
}
