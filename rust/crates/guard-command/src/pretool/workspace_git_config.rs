//! Bounded read of a workspace repository's configuration for the workspace
//! sandbox: helper paths inside the workspace become write-denied so a
//! sandboxed command cannot plant code a later, unsandboxed Git would run.
use super::workspace_git_environment::{global_config_paths, GitVariables};
use config_entries::{entries, names_data};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DENIALS: usize = 64;
const MAX_GLOBAL_FILES: usize = 32;
const MAX_INCLUDE_DEPTH: usize = 4;

/// `Ok(None)` for a missing file, `Ok(Some(text))` for a plain, bounded one,
/// and `Err` for anything this reader cannot reason about (a special file,
/// oversized or binary content, or a symlink unless `follow`). Global files
/// are followed through links; callers first prove the target is outside the
/// workspace.
fn read_config(path: &Path, follow: bool) -> Result<Option<String>, ()> {
    let metadata = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match metadata {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
        Ok(metadata) if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES => return Err(()),
        Ok(_) => {}
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| ())?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES || bytes.contains(&0) {
        return Err(());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| ())
}

/// `Ok(None)` when `root` has no repository, `Ok(Some(text))` for a plain,
/// bounded `.git/config`, and `Err` for anything the sandbox cannot reason
/// about (symlinked `.git`, a gitfile other than a verified linked worktree's,
/// oversized or binary config, or a `config.worktree`, which Git also reads
/// and this reader does not). A linked worktree reads its shared repository's
/// configuration, and the admin entry's `config.worktree` as well.
pub(crate) fn repository_config(root: &Path) -> Result<Option<String>, ()> {
    let git = root.join(".git");
    let directories = match fs::symlink_metadata(&git) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
        Ok(metadata) if metadata.is_dir() => vec![git],
        Ok(metadata) if metadata.is_file() => {
            let (common, admin) = super::worktree_writes::linked_worktree_dirs(root).ok_or(())?;
            vec![common, admin]
        }
        Ok(_) => return Err(()),
    };
    for directory in &directories {
        match fs::symlink_metadata(directory.join("config.worktree")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(()),
        }
    }
    Ok(Some(
        read_config(&directories[0].join("config"), false)?.unwrap_or_default(),
    ))
}

/// The URL of every remote the repository whose work tree is `root` names, or
/// `None` when its configuration cannot be read as plain, bounded entries, or
/// when it rewrites URLs (`url.<base>.insteadOf`) or includes another file, so
/// the URL it names is not the one Git connects to.
pub(super) fn remote_urls(root: &Path) -> Option<Vec<String>> {
    let config = repository_config(root).ok()??;
    let entries = entries(&config)?;
    // Git still reads the deprecated `[url.<base>]` header, which the entry
    // reader names `url.<base>`, so the section is judged by its first part.
    let rewritten = entries.iter().any(|(section, key, _)| {
        let base = section.split('.').next().unwrap_or_default();
        (base == "url" && matches!(key.as_str(), "insteadof" | "pushinsteadof"))
            || (matches!(base, "include" | "includeif") && key == "path")
    });
    (!rewritten).then(|| {
        entries
            .into_iter()
            .filter(|(section, key, _)| section == "remote" && key == "url")
            .map(|(_, _, value)| value)
            .collect()
    })
}

/// The shared Git directory and admin entry of the verified linked worktree
/// whose work tree holds `workspace`, or `None` for any other workspace.
#[cfg(any(unix, test))]
pub(crate) fn linked_git_dirs(workspace: &Path, home: Option<&Path>) -> Option<(PathBuf, PathBuf)> {
    super::worktree_writes::linked_worktree_dirs(&work_tree(workspace, home)?)
}

/// The repository whose work tree holds `workspace`: the workspace itself
/// or the nearest ancestor with a `.git` entry, stopping at `home`.
pub(super) fn work_tree(workspace: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let mut current = Some(workspace);
    while let Some(directory) = current {
        if fs::symlink_metadata(directory.join(".git")).is_ok() {
            return Some(directory.to_path_buf());
        }
        if Some(directory) == home {
            return None;
        }
        current = directory.parent();
    }
    None
}

/// Every workspace path the sandbox must keep unwritable so a later host Git
/// never runs code it planted, or `None` to keep the command at review. It
/// covers the repository whose work tree holds the workspace, which may be
/// an ancestor, and the hook directories and helper programs named by global
/// configuration and the files it includes.
pub(crate) fn workspace_write_denials(
    workspace: &Path,
    home: Option<&Path>,
    variables: &GitVariables,
) -> Option<Vec<PathBuf>> {
    write_denials_from(workspace, home, global_config_paths(home, variables)?)
}

/// [`workspace_write_denials`] with `globals` as the global configuration
/// files, before includes.
fn write_denials_from(
    workspace: &Path,
    home: Option<&Path>,
    globals: Vec<PathBuf>,
) -> Option<Vec<PathBuf>> {
    let root = work_tree(workspace, home);
    let denials = denials_within(root.as_deref(), workspace, home, globals.clone())?;
    // A run in a linked worktree also writes its shared repository's objects
    // and refs, so no helper or global configuration may live there either.
    if let Some((common, _)) = root
        .as_deref()
        .and_then(super::worktree_writes::linked_worktree_dirs)
    {
        if !denials_within(root.as_deref(), &common, home, globals)?.is_empty() {
            return None;
        }
    }
    Some(denials)
}

/// The helper paths under `workspace` that the configuration of the
/// repository at `root`, and `globals` with their includes, name.
fn denials_within(
    root: Option<&Path>,
    workspace: &Path,
    home: Option<&Path>,
    globals: Vec<PathBuf>,
) -> Option<Vec<PathBuf>> {
    let mut denials = match root {
        Some(root) => {
            let config = repository_config(root).ok()?.unwrap_or_default();
            helper_denials(&config, root, workspace, home)?
        }
        None => Vec::new(),
    };
    let base = root.unwrap_or(workspace);
    let mut pending: Vec<(PathBuf, usize)> = globals.into_iter().map(|path| (path, 0)).collect();
    let mut visited = 0usize;
    while let Some((path, depth)) = pending.pop() {
        visited += 1;
        if visited > MAX_GLOBAL_FILES || depth > MAX_INCLUDE_DEPTH {
            return None;
        }
        // A global file the sandbox could write, directly or through a link
        // or a missing parent, could name any helper; keep it at review.
        let resolved = resolve(&path)?;
        if folded_inside(&resolved, workspace) {
            return None;
        }
        let Some(config) = read_config(&path, true).ok()? else {
            continue;
        };
        let directory = resolved.parent()?.to_path_buf();
        for (section, key, value) in entries(&config)? {
            if section.starts_with("include") && key == "path" {
                pending.push((expand(&directory, home, &value)?, depth + 1));
            } else if key == "hookspath" {
                let relative = !value.trim_matches('"').starts_with(['~', '/']);
                let path = expand(base, home, &value)?;
                if relative && !path.starts_with(base) {
                    return None;
                }
                deny_linked(&mut denials, path, workspace)?;
            } else if section != "branch" && section != "user" && !names_data(&section, &key) {
                helper_word_denials(&mut denials, &value, base, home, workspace)?;
            }
        }
    }
    (denials.len() <= MAX_DENIALS).then_some(denials)
}

/// `path` with its longest existing ancestor resolved through links, or
/// `None` when that ancestor cannot be resolved. A dangling link is `None`
/// too: the sandbox could create its target, which host Git would follow.
fn resolve(path: &Path) -> Option<PathBuf> {
    let path = normalize(path);
    let mut existing = path.as_path();
    let mut rest = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(real) => {
                return Some(rest.iter().rev().fold(real, |acc, part| acc.join(part)));
            }
            Err(_) => {
                if existing.symlink_metadata().is_ok() {
                    return None;
                }
                rest.push(existing.file_name()?.to_owned());
                existing = existing.parent()?;
            }
        }
    }
}

/// Whether `path` lies at or under `workspace` when case is ignored, as it
/// is on the default macOS volume.
fn folded_inside(path: &Path, workspace: &Path) -> bool {
    let fold = |path: &Path| PathBuf::from(path.to_string_lossy().to_ascii_lowercase());
    fold(path).starts_with(fold(workspace))
}

/// A configuration path value resolved the way Git does: `~/` against
/// `home`, a relative value against `base`. `None` for a form this reader
/// does not resolve (`~user`, `%(prefix)`, an inline comment, an escape or an
/// expansion), which keeps the command at review.
fn expand(base: &Path, home: Option<&Path>, value: &str) -> Option<PathBuf> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value);
    if value.is_empty() || value.contains(['"', '#', ';', '\\', '$', '`', '%']) {
        return None;
    }
    let path = if value == "~" {
        home?.to_path_buf()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home?.join(rest)
    } else if value.starts_with('~') {
        return None;
    } else {
        base.join(value)
    };
    Some(normalize(&path))
}

/// Adds `path` to the denials when it is inside the workspace. `None` when
/// it is the workspace or holds it, which no denial can express, or when it
/// differs from the workspace only by case.
fn deny(denials: &mut Vec<PathBuf>, path: PathBuf, workspace: &Path) -> Option<()> {
    if workspace.starts_with(&path) || folded_inside(workspace, &path) {
        return None;
    }
    if path.starts_with(workspace) {
        if !denials.contains(&path) {
            if denials.len() >= MAX_DENIALS {
                return None;
            }
            denials.push(path);
        }
    } else if folded_inside(&path, workspace) {
        return None;
    }
    Some(())
}

/// [`deny`] for both the path as written and the path its links lead to.
/// Host Git follows links while the sandbox checks real paths, so a link
/// outside the workspace can lead in, and a link inside it could be swapped
/// for a directory. `None` when the links cannot be resolved.
fn deny_linked(denials: &mut Vec<PathBuf>, path: PathBuf, workspace: &Path) -> Option<()> {
    let real = resolve(&path)?;
    deny(denials, path, workspace)?;
    deny(denials, real, workspace)
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

/// `value` as a path under `workspace`, resolving a relative value against
/// `base`; `None` when it leaves the workspace or is not a plain path.
fn inside(base: &Path, workspace: &Path, value: &str) -> Option<PathBuf> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() || value.starts_with('~') || value.contains("://") {
        return None;
    }
    let normal = normalize(&base.join(value));
    (normal.starts_with(workspace) && normal != workspace).then_some(normal)
}

/// Workspace paths a configured hook directory or helper command names, for
/// a repository whose work tree is the workspace.
#[cfg(test)]
pub(crate) fn helper_write_denials(config: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
    helper_denials(config, workspace, workspace, None)
}

/// Workspace paths a configured hook directory or helper command names. Every
/// one becomes write-denied inside the sandbox. Paths resolve against the
/// work tree `root`; those outside `workspace` but inside `root` cannot be
/// written by the sandbox and are skipped. `None` keeps the command at
/// review: an include of repository configuration this reader never parses,
/// a hook directory outside the work tree, or a list beyond its bound.
fn helper_denials(
    config: &str,
    root: &Path,
    workspace: &Path,
    home: Option<&Path>,
) -> Option<Vec<PathBuf>> {
    let git_dir = root.join(".git");
    let mut denials: Vec<PathBuf> = Vec::new();
    for (section, key, value) in entries(config)? {
        let section = section.as_str();
        let key = key.as_str();
        let mut candidates: Vec<PathBuf> = Vec::new();
        if section.starts_with("include") && key == "path" {
            // Git resolves a relative include against the including file's
            // directory, `.git/`. Included repository configuration could
            // name its own helpers, and this reader does not follow it.
            if inside(&git_dir, root, &value).is_some() {
                return None;
            }
        } else if key == "hookspath" {
            // Relative hook directories resolve against the work tree. An
            // inline comment or escape would move the path Git uses.
            if value.contains(['#', ';', '\\']) {
                return None;
            }
            candidates.push(inside(root, root, &value)?);
        } else if section != "branch" && section != "user" && !names_data(section, key) {
            helper_word_denials(&mut denials, &value, root, home, workspace)?;
        }
        for path in candidates {
            // An unbounded list, or a path that is or holds the workspace,
            // cannot be denied; keep the command at review.
            deny_linked(&mut denials, path, workspace)?;
        }
    }
    Some(denials)
}

/// Denies each workspace path a helper value could run or hand to a shell.
/// The first word is a program Git finds on PATH unless it has a slash.
/// Later words are arguments a shell may resolve in the repository, so each
/// one is denied whether or not it exists yet: the sandbox could otherwise
/// create it for a later host command. Shell separators and grouping split
/// words too, so `./x.sh;` and `./a&&git` deny `x.sh` and `a`. Globs and brace
/// expansions keep the command at review, because the sandbox could create a
/// file a pattern later matches; a brace on its own is a command group. So
/// does any expansion except a whole-word variable such as `$LOCAL`, which
/// Git or the environment sets at run time and the sandbox cannot change.
fn helper_word_denials(
    denials: &mut Vec<PathBuf>,
    value: &str,
    base: &Path,
    home: Option<&Path>,
    workspace: &Path,
) -> Option<()> {
    if value.contains(['`', '\\', '*', '?', '[']) {
        return None;
    }
    // A quoted word with whitespace names one path that the splitter below
    // would break apart, so keep it at review. Scan before trimming so an
    // opening quote still counts.
    let mut quote = None;
    for c in value.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) if c.is_whitespace() => return None,
            _ => {}
        }
    }
    let value = value
        .trim_start_matches(['"', '\''])
        .trim_start_matches('!');
    if value
        .split(|c: char| c.is_whitespace() || ";&|()<>".contains(c))
        .map(|word| word.trim_matches(['"', '\'']))
        .any(|word| word.contains(['{', '}']) && word != "{" && word != "}")
    {
        return None;
    }
    let words = value
        .split(|c: char| c.is_whitespace() || ";&|(){}<>".contains(c))
        .filter(|word| !word.is_empty());
    for (index, word) in words.enumerate() {
        let word = word.trim_matches(|c| c == '"' || c == '\'');
        let word = match word.split_once('=') {
            Some((option, value)) if option.starts_with('-') => value,
            _ => word,
        };
        if word.contains('$') {
            if bare_variable(word) {
                continue;
            }
            return None;
        }
        if word.is_empty()
            || word.starts_with('-')
            || word.contains("://")
            || !(word.contains('/') || index > 0)
        {
            continue;
        }
        let path = if word == "~" {
            continue;
        } else if let Some(rest) = word.strip_prefix("~/") {
            home?.join(rest)
        } else if word.starts_with('~') {
            return None;
        } else {
            base.join(word)
        };
        let path = normalize(&path);
        // A word naming the workspace or a directory that holds it is not a
        // program the sandbox could plant.
        if workspace.starts_with(&path) || folded_inside(workspace, &path) {
            continue;
        }
        deny_linked(denials, path, workspace)?;
    }
    Some(())
}

/// `$NAME`, `$1` or `$@` as a whole word.
fn bare_variable(word: &str) -> bool {
    let Some(name) = word.strip_prefix('$') else {
        return false;
    };
    let digits = !name.is_empty() && name.chars().all(|c| c.is_ascii_digit());
    let identifier = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    matches!(name, "@" | "#") || digits || identifier
}

#[path = "workspace_git_config_entries.rs"]
mod config_entries;

#[cfg(test)]
#[path = "workspace_git_config_tests.rs"]
mod tests;
