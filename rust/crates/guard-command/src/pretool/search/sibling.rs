//! `rg` roots that name another repository below home.
//!
//! Agents in one repository spell a sibling as an absolute, `~` or `../`
//! path. A `.git` directory and its ignored build output would make the
//! ordinary metadata walk refuse almost every such root, so this walk follows
//! what `rg` itself searches by default instead: it skips hidden entries and
//! directories the repository's root `.gitignore` names plainly, and screens
//! every other descendant like a recursive read.
//!
//! The model holds only while ignore rules cannot widen the search. An ignore
//! file can whitelist a hidden file such as `.env`, and `rg` searches inside a
//! directory named on its command line even when that directory is ignored.
//! So every component between the repository root and the named directory
//! must be visible, or a hidden project-metadata directory such as `.github`,
//! and not plainly ignored, and any `.ignore` or `.rgignore` file sends the
//! search to review. A negated pattern in a `.gitignore` or the repository's
//! `info/exclude` is admitted only when it re-includes a literal path, such
//! as `!.gitkeep` or `!.vscode/settings.json`, whose name is not a secret and
//! that this walk does not prune; hidden entries with that name are then
//! screened like any other descendant.
use super::{tree, ReadContext};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 10_000;
const MAX_DEPTH: usize = 64;
const MAX_IGNORE_BYTES: u64 = 64 * 1024;
const WHITELISTING_FILES: [&str; 2] = [".ignore", ".rgignore"];

/// True when `value` names a directory of a git working tree strictly below
/// home and every file `rg` would search there clears the descendant screen.
pub(in crate::pretool) fn rg_sibling_repository_root(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(tree::HAZARDS)
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || (value.starts_with('~') && value != "~" && !value.starts_with("~/"))
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(operand) =
        tree::expanded_operand(value, context).and_then(|path| std::fs::canonicalize(path).ok())
    else {
        return false;
    };
    let Some(root) = operand
        .ancestors()
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())
    else {
        return false;
    };
    operand.is_dir()
        && super::super::git_routes::repository_below_home(root, context)
        && no_whitelisting_ancestor(&operand, context)
        && match ignored_names(root) {
            Some(mut ignored) => {
                reachable_by_default(root, &operand, &mut ignored)
                    && walk(root, &operand, &mut ignored)
            }
            None => false,
        }
}

/// `rg` searches a named directory even when it is ignored or hidden, and
/// would then apply no rule this walk prunes by. Each component from the
/// repository root down to `operand` must be one `rg` reaches on its own, and
/// each intermediate `.gitignore` may negate only an admitted literal path.
fn reachable_by_default(root: &Path, operand: &Path, ignored: &mut Ignored) -> bool {
    let Ok(relative) = operand.strip_prefix(root) else {
        return false;
    };
    let mut directory = root.to_path_buf();
    for (index, component) in relative.components().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        // `rg` skips a hidden directory on its own, but searches one named on
        // its command line. Only a project-metadata name the recursive walk
        // also admits, such as `.github`, may be named; `.git` never is.
        let refused_hidden =
            name.starts_with('.') && !tree::descendant_allowed(&directory.join(name), root, false);
        if refused_hidden || ignored.prunes(name, index == 0) {
            return false;
        }
        directory.push(name);
        if directory != operand && !ignored.admit_ignore_file(root, &directory) {
            return false;
        }
    }
    true
}

/// `rg` also reads `.ignore` and `.rgignore` files in parent directories.
fn no_whitelisting_ancestor(operand: &Path, context: ReadContext<'_>) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    operand
        .ancestors()
        .skip(1)
        .take_while(|path| path.starts_with(&home))
        .all(|path| {
            WHITELISTING_FILES
                .iter()
                .all(|name| std::fs::symlink_metadata(path.join(name)).is_err())
        })
}

/// Names the root `.gitignore` ignores at any depth, and names it ignores
/// only directly below the root. Only plain names are used to prune; every
/// other pattern just leaves its matches to the descendant screen.
struct Ignored {
    anywhere: Vec<String>,
    at_root: Vec<String>,
    /// Final names of the paths negated patterns re-include. `rg` searches
    /// such an entry even when it is hidden, so the walk screens hidden
    /// entries with any of these names wherever they appear.
    whitelisted: Vec<String>,
}

impl Ignored {
    fn prunes(&self, name: &str, directly_below_root: bool) -> bool {
        self.anywhere.iter().any(|ignored| ignored == name)
            || (directly_below_root && self.at_root.iter().any(|ignored| ignored == name))
    }

    fn whitelists(&self, name: &str) -> bool {
        self.whitelisted
            .iter()
            .any(|whitelisted| whitelisted.eq_ignore_ascii_case(name))
    }

    /// Reads the `.gitignore` in `directory`, if any, and admits its
    /// negated patterns.
    fn admit_ignore_file(&mut self, root: &Path, directory: &Path) -> bool {
        match optional_ignore_lines(&directory.join(".gitignore")) {
            Some(Some(lines)) => self.admit_negations(root, directory, &lines),
            Some(None) => true,
            None => false,
        }
    }

    /// Records the negated patterns among `lines`, read from an ignore file
    /// that applies below `base`. A negation may only re-include a literal
    /// path whose components this walk never prunes, so a plainly ignored
    /// directory stays out of `rg`'s reach, and whose name is not a secret
    /// the descendant screen would refuse.
    fn admit_negations(&mut self, root: &Path, base: &Path, lines: &[String]) -> bool {
        for line in lines {
            let Some(pattern) = line.strip_prefix('!') else {
                continue;
            };
            let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
            let pattern = pattern.strip_suffix('/').unwrap_or(pattern);
            let components: Vec<&str> = pattern.split('/').collect();
            let literal = components.iter().all(|component| plain_name(component));
            let pruned = components.iter().any(|component| {
                self.anywhere
                    .iter()
                    .chain(&self.at_root)
                    .any(|ignored| ignored.eq_ignore_ascii_case(component))
            });
            let Some(name) = components.last().filter(|_| literal && !pruned) else {
                return false;
            };
            if !tree::descendant_allowed(&base.join(pattern), root, true) {
                return false;
            }
            self.whitelisted.push((*name).to_owned());
        }
        true
    }
}

/// A name of letters, digits, `_`, `-` and `.` that matches only itself.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn ignored_names(root: &Path) -> Option<Ignored> {
    let mut ignored = Ignored {
        anywhere: Vec::new(),
        at_root: Vec::new(),
        whitelisted: Vec::new(),
    };
    let mut excludes = Vec::new();
    for git_dir in git_directories(root)? {
        excludes.extend(optional_ignore_lines(&git_dir.join("info/exclude"))?.unwrap_or_default());
    }
    let lines = optional_ignore_lines(&root.join(".gitignore"))?.unwrap_or_default();
    for line in &lines {
        let pattern = line.strip_suffix('/').unwrap_or(line);
        let (anchored, name) = match pattern.strip_prefix('/') {
            Some(name) => (true, name),
            None => (false, pattern),
        };
        if !plain_name(name) {
            continue;
        }
        if anchored {
            ignored.at_root.push(name.to_owned());
        } else {
            ignored.anywhere.push(name.to_owned());
        }
    }
    (ignored.admit_negations(root, root, &excludes) && ignored.admit_negations(root, root, &lines))
        .then_some(ignored)
}

/// The git directories whose `info/exclude` `rg` may read: `.git` itself, or
/// for a linked worktree its registry entry and the owning repository's.
fn git_directories(root: &Path) -> Option<Vec<PathBuf>> {
    let dot_git = root.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git).ok()?;
    if metadata.is_dir() {
        return Some(vec![dot_git]);
    }
    let lines = ignore_lines(&dot_git)?;
    let entry = PathBuf::from(lines.first()?.strip_prefix("gitdir: ")?);
    let entry = if entry.is_absolute() {
        entry
    } else {
        root.join(entry)
    };
    let common = entry.parent()?.parent()?.to_path_buf();
    Some(vec![entry, common])
}

/// `Some(None)` when the file is absent, `None` when it cannot be trusted.
fn optional_ignore_lines(path: &Path) -> Option<Option<Vec<String>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
        Ok(metadata) if metadata.is_file() => ignore_lines(path).map(Some),
        _ => None,
    }
}

/// Pattern lines of a bounded regular ignore file, or `None` when the file
/// cannot be read.
fn ignore_lines(path: &Path) -> Option<Vec<String>> {
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_IGNORE_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_IGNORE_BYTES {
        return None;
    }
    let mut lines = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines.push(line.to_owned());
    }
    Some(lines)
}

fn walk(root: &Path, operand: &Path, ignored: &mut Ignored) -> bool {
    let mut pending: Vec<(PathBuf, usize)> = vec![(operand.to_path_buf(), 0)];
    let mut inspected = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return false;
        }
        // The directory's own `.gitignore` applies to its entries, so its
        // negations are admitted before any entry is screened.
        if directory != root && !ignored.admit_ignore_file(root, &directory) {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else { return false };
            inspected += 1;
            if inspected > MAX_ENTRIES {
                return false;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            if WHITELISTING_FILES.contains(&name) {
                return false;
            }
            // `rg` skips hidden entries unless a negated pattern re-includes
            // them; ignore files themselves were read above.
            if name == ".gitignore" || (name.starts_with('.') && !ignored.whitelists(name)) {
                continue;
            }
            if ignored.prunes(name, directory == root) {
                continue;
            }
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                return false;
            };
            if !tree::descendant_allowed(&path, root, metadata.is_file()) {
                return false;
            }
            if metadata.is_dir() {
                pending.push((path, depth + 1));
            } else if !metadata.is_file() {
                return false;
            }
        }
    }
    true
}
