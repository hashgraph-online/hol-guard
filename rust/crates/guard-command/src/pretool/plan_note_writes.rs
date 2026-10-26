//! Plan notes an agent files in its own harness home.
//!
//! Codex and Claude Code keep their plan documents in `~/.codex/plans` and
//! `~/.claude/plans`. Both directories sit inside a harness home that also
//! holds configuration, hooks and instructions, so every write there was held
//! for review, and because each note has its own name a saved approval never
//! covered the next one. A plan document runs nothing and no harness loads it
//! as configuration, so a regular Markdown file directly inside one of those
//! directories is an ordinary write, like a document in a repository.
//!
//! Nothing else below a harness home is: configuration, hooks, rules, skills
//! and instruction files, a note in a subfolder, a hidden or non-Markdown
//! name, a path reached through a link, and a home that itself lies inside a
//! harness directory all keep their review. Every other write screen still
//! applies to the note.

use std::path::{Component, Path};

use super::super::read_paths::expand_home_read_path;
use crate::harness_config_names::{path_parts_protected, HARNESS_INSTRUCTION_FILES};

/// The harness plan directories below the user's home.
const PLAN_DIRECTORIES: [[&str; 2]; 2] = [[".codex", "plans"], [".claude", "plans"]];

/// The ordinary names of `path`, or `None` when one is not valid UTF-8.
fn normal_parts(path: &Path) -> Option<Vec<&str>> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_str()),
            _ => None,
        })
        .collect()
}

/// A visible Markdown name that is not an agent instruction file.
fn plan_note_name(name: &str) -> bool {
    !name.starts_with('.')
        && Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
        && !name
            .chars()
            .any(|value| value.is_control() || matches!(value, ':' | '\\' | '/'))
        && !HARNESS_INSTRUCTION_FILES.contains(&name.to_ascii_lowercase().as_str())
}

/// Whether the resolved `canonical` path is a Markdown file directly inside a
/// plan directory of the verified, resolved `home`, with the directory in
/// place as a real folder, and not an existing program. The caller has
/// resolved every link and applies the remaining write screens.
pub(super) fn plan_note_path(canonical: &Path, home: &Path) -> bool {
    let Some(home_parts) = normal_parts(home) else {
        return false;
    };
    // A home that lies inside a harness directory is not a home to trust here.
    if path_parts_protected(home_parts.iter().copied()) {
        return false;
    }
    let Some(parts) = canonical
        .strip_prefix(home)
        .ok()
        .and_then(normal_parts)
        .filter(|parts| parts.len() == 3)
    else {
        return false;
    };
    PLAN_DIRECTORIES.contains(&[parts[0], parts[1]])
        && plan_note_name(parts[2])
        // Truncating an existing program replaces what a later step may run.
        // The resolved path is checked, so a `~` spelling cannot hide an
        // execute bit from a check that reads it relative to the working
        // directory.
        && !canonical.to_str().is_none_or(|canonical| {
            crate::pretool::curl_reads::output_targets::existing_executable(canonical, None)
        })
        && canonical
            .parent()
            .and_then(|directory| std::fs::symlink_metadata(directory).ok())
            .is_some_and(|metadata| metadata.is_dir())
}

/// A write target that is a plan note and passes the whole bounded write
/// proof. Redirect and heredoc targets use it, because `~` and home-rooted
/// spellings are otherwise never removed from a command.
pub(in crate::pretool) fn plan_note_write_target(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if !value.contains("/plans/") {
        return false;
    }
    let Some(home) = home_dir.and_then(|home| std::fs::canonicalize(home).ok()) else {
        return false;
    };
    let expanded = expand_home_read_path(value, home_dir).unwrap_or_else(|| value.to_owned());
    let path = Path::new(&expanded);
    path.is_absolute()
        && super::super::worktree_writes::canonical_write_target(path)
            .is_some_and(|canonical| plan_note_path(&canonical, &home))
        && super::bounded_native_file_write_target(value, home_dir, cwd)
}

/// The operands a plain `cp` or `touch` only reads, when the whole command
/// passes its bounded proof and every path it writes is a plan note. `cp`
/// reads its one source; `touch` reads nothing. The command-extension layer
/// holds any write that names a harness directory, and this tells it the one
/// such write that changes no configuration. What the sources are called is
/// left to the caller.
pub(crate) fn plan_note_write_sources<'a>(
    command: &str,
    arguments: &'a [String],
    context: super::super::PathContext<'_>,
) -> Option<&'a [String]> {
    let operands = match arguments {
        [separator, rest @ ..] if separator == "--" => rest,
        _ => arguments,
    };
    let note = |value: &str| plan_note_write_target(value, context.home_dir, context.cwd);
    match (command, operands) {
        ("cp", [source, destination]) => {
            // A destination folder takes the source's own name.
            let named = Path::new(source)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| note(&format!("{}/{name}", destination.trim_end_matches('/'))));
            ((note(destination) || named) && super::safe_copy_arguments(arguments, context))
                .then(|| std::slice::from_ref(source))
        }
        ("touch", [target]) => (note(target)
            && super::safe_file_mutation_arguments(command, arguments, context))
        .then_some(&[][..]),
        _ => None,
    }
}

#[cfg(test)]
#[path = "plan_note_writes_tests.rs"]
mod tests;
