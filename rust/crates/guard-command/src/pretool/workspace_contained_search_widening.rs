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

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[cfg(test)]
#[path = "workspace_contained_search_widening_walk_tests.rs"]
mod walk_tests;

/// How many directory entries the hidden-entry walk may read. A tree larger
/// than this cannot be answered before the command runs, so it keeps review.
const MAX_INSPECTED: usize = 20_000;

/// Lines read from one ignore file, and parent directories searched for them.
const MAX_IGNORE_LINES: usize = 1_024;
const MAX_ANCESTORS: usize = 32;

/// A name no real entry has, standing for "anything inside this directory".
const INSIDE: &str = "\u{1}";

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
    let mut pending: Vec<Pending> = roots
        .iter()
        .map(|root| Pending {
            directory: root.clone(),
            hidden: false,
            matched: false,
            in_repository: in_repository(root),
            ignored_names: Rc::new(ancestor_ignored_names(root)),
        })
        .collect();
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current.directory) else {
            continue;
        };
        // ripgrep reads `.gitignore` only inside a git repository.
        let local = if current.in_repository {
            IgnoredNames::read(&current.directory)
        } else {
            IgnoredNames::default()
        };
        let below = if local.anywhere.is_empty() {
            Rc::clone(&current.ignored_names)
        } else {
            let mut names = (*current.ignored_names).clone();
            names.extend(local.anywhere.iter().cloned());
            Rc::new(names)
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
            let hidden = current.hidden || name.starts_with('.');
            let matched = current.matched || included(&path, &name, cwd, inclusions);
            if kind.is_dir() {
                // A hidden or ignored directory is entered only when a glob
                // names it or could name something inside it.
                let ignored = !local.kept.contains(name.as_ref())
                    && (local.here.contains(name.as_ref()) || below.contains(name.as_ref()));
                if (name.starts_with('.') || ignored)
                    && !matched
                    && !included(&path.join(INSIDE), INSIDE, cwd, inclusions)
                {
                    continue;
                }
                pending.push(Pending {
                    directory: path,
                    hidden,
                    matched,
                    in_repository: current.in_repository,
                    ignored_names: Rc::clone(&below),
                });
            } else if hidden && matched && !TOOL_DOTFILES.contains(&name.as_ref()) {
                return true;
            }
        }
    }
    false
}

struct Pending {
    directory: PathBuf,
    /// Inside a hidden directory.
    hidden: bool,
    /// Inside a directory an inclusion glob names.
    matched: bool,
    /// Inside a git repository, where ripgrep honours `.gitignore`.
    in_repository: bool,
    /// Directory names an ignore file above this one excludes at any depth.
    ignored_names: Rc<HashSet<String>>,
}

/// The plain directory names one `.gitignore` excludes. Only literal names
/// are read: a rule with a wildcard or an inner `/` is left out, which only
/// makes the walk read more, never less.
#[derive(Default)]
struct IgnoredNames {
    /// Unanchored names, excluded at any depth below this directory.
    anywhere: HashSet<String>,
    /// `/name` rules, excluded only directly inside this directory.
    here: HashSet<String>,
    /// Names a `!` rule here puts back; never pruned.
    kept: HashSet<String>,
}

impl IgnoredNames {
    fn read(directory: &Path) -> Self {
        let mut names = Self::default();
        let Ok(text) = std::fs::read_to_string(directory.join(".gitignore")) else {
            return names;
        };
        for line in text.lines().take(MAX_IGNORE_LINES) {
            let line = line.trim();
            let (negated, rule) = match line.strip_prefix('!') {
                Some(rule) => (true, rule),
                None => (false, line),
            };
            if rule.is_empty() || rule.starts_with('#') {
                continue;
            }
            let anchored = rule.starts_with('/');
            let name = rule.trim_start_matches('/').trim_end_matches('/');
            if name.is_empty() || name.contains(['/', '*', '?', '[', '\\']) {
                continue;
            }
            if negated {
                names.kept.insert(name.to_owned());
            } else if anchored {
                names.here.insert(name.to_owned());
            } else {
                names.anywhere.insert(name.to_owned());
            }
        }
        names.anywhere.retain(|name| !names.kept.contains(name));
        names
    }
}

fn in_repository(root: &Path) -> bool {
    root.ancestors()
        .take(MAX_ANCESTORS)
        .any(|ancestor| ancestor.join(".git").exists())
}

/// Unanchored names the `.gitignore` files between `root` and its repository
/// top exclude. ripgrep reads those ancestors too.
fn ancestor_ignored_names(root: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    if !in_repository(root) {
        return names;
    }
    for ancestor in root.ancestors().skip(1).take(MAX_ANCESTORS) {
        names.extend(IgnoredNames::read(ancestor).anywhere);
        if ancestor.join(".git").exists() {
            break;
        }
    }
    if root.join(".git").exists() {
        names.clear();
    }
    names
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
