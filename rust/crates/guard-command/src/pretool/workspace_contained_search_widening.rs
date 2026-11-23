//! A search told to look past ignore rules stays at review.
//!
//! `rg` skips hidden and ignored files unless a glob override (`--glob`,
//! `--iglob`), `--hidden`, `--no-ignore` or `-u` widens it. Those are the
//! files a repository keeps its local secrets in, and the read review stops
//! these searches because it cannot prove what they reach. The sandbox
//! withholds only a fixed list of credential paths, so a contained run would
//! still read a secret kept under any other name and print it.
//!
//! An inclusion glob is the common case: `rg --files -g '*.md'` is how agents
//! list files. ripgrep lets a whitelisting glob bring back a hidden entry, so
//! a glob keeps the review only when the search roots hold a hidden entry the
//! glob actually brings back. Every other way of widening keeps it outright.

use std::path::{Path, PathBuf};

/// How many directory entries the hidden-entry walk may read. A tree larger
/// than this cannot be answered before the command runs, so it keeps review.
const MAX_INSPECTED: usize = 20_000;

/// Dotfiles a repository commits for its tools; none of them holds a secret.
const TOOL_DOTFILES: &[&str] = &[
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    ".keep",
    ".ignore",
    ".rgignore",
];

/// Whether a segment runs `rg` so that it reaches hidden or ignored files.
/// `cwd` is the directory the command's relative paths resolve against.
pub(super) fn widens_past_ignore_rules(model: &crate::CanonicalCommandV1, cwd: &Path) -> bool {
    model.segments.iter().any(|segment| {
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        executable.rsplit('/').next() == Some("rg") && segment_widens(&segment.arguments, cwd)
    })
}

struct Inclusion {
    text: String,
    ignore_case: bool,
}

fn segment_widens(arguments: &[String], cwd: &Path) -> bool {
    let mut inclusions = Vec::new();
    let mut operands = Vec::new();
    // `--` is not read as the end of options: `--context-separator --` takes
    // it as a value, so a flag after it may still be live.
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let glob = if let Some(long) = argument.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (long, None),
            };
            if matches!(name, "hidden" | "unrestricted" | "follow") || name.starts_with("no-ignore")
            {
                return true;
            }
            if !matches!(name, "glob" | "iglob") {
                continue;
            }
            let Some(value) = value.or_else(|| arguments.next().cloned()) else {
                return true;
            };
            Some((value, name == "iglob"))
        } else if let Some(letters) = argument
            .strip_prefix('-')
            .filter(|letters| !letters.is_empty())
        {
            // A short bundle such as `-nu` or `-g*.ts`; letters after `g` are its value.
            let (flags, value) = match letters.split_once('g') {
                Some((flags, value)) => (flags, Some(value)),
                None => (letters, None),
            };
            if flags.contains(['u', '.', 'L']) {
                return true;
            }
            match value {
                None => continue,
                Some("") => match arguments.next() {
                    Some(value) => Some((value.clone(), false)),
                    None => return true,
                },
                Some(value) => Some((value.to_owned(), false)),
            }
        } else {
            operands.push(argument.as_str());
            None
        };
        if let Some((text, ignore_case)) = glob {
            // An exclusion glob only removes files from the search.
            if !text.starts_with('!') {
                inclusions.push(Inclusion { text, ignore_case });
            }
        }
    }
    if inclusions.is_empty() {
        return false;
    }
    // The pattern cannot be told from a root by position alone, so every
    // operand naming a directory is walked; with none, ripgrep searches `cwd`.
    let mut roots: Vec<PathBuf> = operands
        .iter()
        .map(|operand| cwd.join(operand))
        .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))
        .collect();
    if roots.is_empty() {
        roots.push(cwd.to_path_buf());
    }
    brings_back_hidden_entry(&roots, cwd, &inclusions)
}

/// Whether walking `roots` the way ripgrep does with these inclusion globs
/// reaches a hidden file, or a file inside a hidden directory.
fn brings_back_hidden_entry(roots: &[PathBuf], cwd: &Path, inclusions: &[Inclusion]) -> bool {
    let mut inspected = 0_usize;
    // (directory, inside a hidden directory, inside a matched directory)
    let mut pending: Vec<(PathBuf, bool, bool)> = roots
        .iter()
        .map(|root| (root.clone(), false, false))
        .collect();
    while let Some((directory, hidden_parent, matched_parent)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
            inspected += 1;
            if inspected > MAX_INSPECTED {
                return true;
            }
            let Ok(entry) = entry else {
                return true;
            };
            let Ok(kind) = entry.file_type() else {
                return true;
            };
            // ripgrep does not follow links without `--follow`.
            if kind.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let hidden = hidden_parent || name.starts_with('.');
            let matched = matched_parent || included(&path, &name, cwd, inclusions);
            if kind.is_dir() {
                // A hidden directory is entered only when a glob names it.
                if name.starts_with('.') && !matched {
                    continue;
                }
                pending.push((path, hidden, matched));
            } else if hidden && matched && !TOOL_DOTFILES.contains(&name.as_ref()) {
                return true;
            }
        }
    }
    false
}

/// Whether one inclusion glob names this entry, read the way ripgrep reads an
/// override: a glob without `/` matches the name at any depth, one with `/`
/// matches the path from the working directory. A glob this matcher cannot
/// read counts as a match.
fn included(path: &Path, name: &str, cwd: &Path, inclusions: &[Inclusion]) -> bool {
    let relative = path
        .strip_prefix(cwd)
        .ok()
        .and_then(|relative| relative.to_str())
        .map(|relative| relative.replace('\\', "/"));
    inclusions.iter().any(|inclusion| {
        let fold = |text: &str| {
            if inclusion.ignore_case {
                text.to_lowercase()
            } else {
                text.to_owned()
            }
        };
        let glob = fold(inclusion.text.trim_start_matches('/').trim_end_matches('/'));
        let Ok(alternatives) = crate::pretool::search_scope_glob::expand_braces(&glob) else {
            return true;
        };
        alternatives.iter().any(|alternative| {
            let subject = if alternative.contains('/') || inclusion.text.starts_with('/') {
                match &relative {
                    Some(relative) => fold(relative),
                    None => return true,
                }
            } else {
                fold(name)
            };
            crate::pretool::search_scope_glob::glob_matches(alternative, &subject).unwrap_or(true)
        })
    })
}
