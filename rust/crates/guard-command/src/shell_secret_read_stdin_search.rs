//! A search tool given a home dotfile's path as its only word.
//!
//! `grep ~/.secrets/key.txt` names no file to search: the path is grep's
//! pattern and grep reads standard input. The operand reader is right to skip
//! it, so the read-only lookup lane saw no target and passed the search, while
//! `sed`, `awk`, `tr`, `ag` and every other reader with the same shape went to
//! review. An agent never needs a search whose only word is the path of a file
//! in the user's private home directories; that word is the read it meant to
//! make, so the lane stops vouching for it and the ordinary review applies.
//!
//! The rule stays narrow so ordinary searches never reach it:
//! - grep must not be recursive, so `grep -r ~/.aws/credentials .` still
//!   searches the tree for references to that path;
//! - there must be no file operand and no `-e`/`-f` pattern option;
//! - the pattern must be written as a path under the home directory whose
//!   first component is hidden (`~/.ssh/…`, `$HOME/.config/…`), so word
//!   patterns and paths inside a project are never treated as reads.
//!
//! Only a search with no other input counts, so a fed search such as
//! `ps aux | grep ~/.ssh/id_rsa` or `grep ~/.ssh/id_rsa < notes.txt` is
//! never asked. `pretool::lone_home_dotpath_search` applies the rule to a
//! whole command: no exact-safe proof vouches for it, and an enabled
//! extension permission cannot settle the review it keeps.

use std::path::Path;

const GREP_FAMILY: &[&str] = &["grep", "egrep", "fgrep"];
const PATTERN_OPTIONS: &[&str] = &["-e", "--regexp", "-f", "--file"];
const VALUE_OPTIONS: &[&str] = &[
    "-A",
    "-B",
    "-C",
    "-D",
    "-g",
    "-m",
    "-t",
    "-T",
    "--after-context",
    "--before-context",
    "--context",
    "--devices",
    "--exclude",
    "--exclude-dir",
    "--glob",
    "--iglob",
    "--include",
    "--max-count",
    "--max-depth",
    "--max-filesize",
    "--type",
    "--type-not",
];

/// Whether this `grep`/`rg` call's only word is a path into a hidden entry
/// of the home directory.
pub(crate) fn lone_search_pattern_names_home_dotpath(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    let Some(pattern) = lone_pattern(command, args) else {
        return false;
    };
    let relative = if let Some(rest) = pattern.strip_prefix("~/") {
        rest.to_owned()
    } else if let Some(rest) = pattern.strip_prefix("$HOME/") {
        rest.to_owned()
    } else if let Some(rest) = pattern.strip_prefix("${HOME}/") {
        rest.to_owned()
    } else {
        let Some(home) = home_dir else {
            return false;
        };
        match under_home(Path::new(pattern), home) {
            Some(rest) => rest,
            None => return false,
        }
    };
    let first = relative.split('/').next().unwrap_or("");
    first.len() > 1 && first.starts_with('.') && first != ".."
}

fn lone_pattern<'a>(command: &str, args: &'a [String]) -> Option<&'a str> {
    let grep_like = GREP_FAMILY.contains(&command);
    if !grep_like && command != "rg" {
        return None;
    }
    let mut pattern: Option<&str> = None;
    let mut skip_value = false;
    let mut after_options = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if after_options || !arg.starts_with('-') || arg == "-" {
            if arg == "-" || pattern.is_some() {
                // A second word is a file operand (or stdin named outright).
                return None;
            }
            pattern = Some(arg);
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        let flag = arg.split_once('=').map_or(arg.as_str(), |(f, _)| f);
        if PATTERN_OPTIONS.contains(&flag)
            || (!arg.starts_with("--") && (arg.starts_with("-e") || arg.starts_with("-f")))
        {
            return None;
        }
        if command == "rg" && matches!(flag, "--files" | "--type-list") {
            return None;
        }
        if grep_like && grep_flag_recurses(arg, flag) {
            return None;
        }
        if VALUE_OPTIONS.contains(&arg.as_str()) {
            skip_value = true;
        }
    }
    pattern
}

fn grep_flag_recurses(arg: &str, flag: &str) -> bool {
    if matches!(
        flag,
        "--recursive" | "--dereference-recursive" | "--directories" | "-d"
    ) {
        return true;
    }
    !arg.starts_with("--") && arg[1..].chars().any(|c| matches!(c, 'r' | 'R' | 'd'))
}

/// The pattern's path below the home directory, matching either spelling of
/// each side: macOS reports `/tmp/...` and `/private/tmp/...` for one place.
fn under_home(pattern: &Path, home: &Path) -> Option<String> {
    let homes = [Some(home.to_path_buf()), std::fs::canonicalize(home).ok()];
    let patterns = [Some(pattern.to_path_buf()), canonical_prefix(pattern)];
    for home in homes.iter().flatten() {
        for pattern in patterns.iter().flatten() {
            if let Ok(rest) = pattern.strip_prefix(home) {
                return Some(rest.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// The path with its deepest existing ancestor resolved, so a missing file
/// under a symlinked directory still resolves.
fn canonical_prefix(path: &Path) -> Option<std::path::PathBuf> {
    let mut tail = Vec::new();
    let mut current = path;
    loop {
        if let Ok(resolved) = std::fs::canonicalize(current) {
            return Some(tail.iter().rev().fold(resolved, |acc, part| acc.join(part)));
        }
        tail.push(current.file_name()?.to_owned());
        current = current.parent()?;
    }
}
