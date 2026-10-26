//! Path matching for Pi detection: `Path.expanduser()`, `Path.rglob()` and
//! `glob.glob(pattern, recursive=True)` for the Pi settings resolver, over a
//! normalized `str(Path)` pattern. Components before the first wildcard are a
//! literal prefix; a wildcard component lists its directory (skipping hidden
//! names unless the component itself starts with a dot) and matches with
//! `fnmatch`; a later literal component must exist (`lexists`); `**` yields
//! the directory and every non-hidden descendant, following directory links.
//! Results are filesystem paths for the caller to `resolve()`, so a directory
//! reached twice through links is listed once: the resolved set is the same.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use guard_command::codex_output_fnmatch::fnmatchcase;

use super::aibom_paths::py_path;
use super::zcode_detect::sort_key;

pub(crate) const ERR_NAME: &str = "native_runner_authority_pi_name_undecodable";
const ERR_HOME: &str = "native_runner_authority_pi_home_unknown";

pub(crate) fn has_magic(text: &str) -> bool {
    text.contains(['*', '?', '['])
}

fn lexists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn is_dir(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

/// `fnmatch.filter`: case-folded where `os.path.normcase` folds.
fn name_matches(name: &str, pattern: &str) -> bool {
    if cfg!(windows) {
        fnmatchcase(&name.to_lowercase(), &pattern.to_lowercase())
    } else {
        fnmatchcase(name, pattern)
    }
}

/// `_iterdir` + `_ishidden`: names in `directory`, directories only when
/// `dironly` (following links), hidden names dropped unless `keep_hidden`.
/// An undecodable name the filter would keep is refused.
fn names(
    directory: &Path,
    dironly: bool,
    keep_hidden: bool,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<String>, &'static str> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(Vec::new());
    };
    let mut kept = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        if dironly && !is_dir(&entry.path()) {
            continue;
        }
        let raw = entry.file_name();
        let lossy = raw.to_string_lossy();
        if !keep_hidden && lossy.starts_with('.') {
            continue;
        }
        if !wanted(&lossy) {
            continue;
        }
        kept.push(raw.into_string().map_err(|_| ERR_NAME)?);
    }
    Ok(kept)
}

/// `_glob2`: the directory itself, then `_rlistdir`.
fn recursive(directory: &Path, dironly: bool, out: &mut Vec<PathBuf>) -> Result<(), &'static str> {
    if is_dir(directory) {
        out.push(directory.to_path_buf());
    }
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        let Ok(canonical) = fs::canonicalize(&current) else {
            continue;
        };
        if !visited.insert(canonical) {
            continue;
        }
        for name in names(&current, dironly, false, |_| true)? {
            let child = current.join(name);
            out.push(child.clone());
            if is_dir(&child) {
                pending.push(child);
            }
        }
    }
    Ok(())
}

/// The paths `glob.glob(pattern, recursive=True)` yields, as filesystem
/// paths; a relative pattern is read from `cwd`. Callers only pass a pattern
/// with a wildcard.
pub(crate) fn glob(pattern: &str, cwd: &Path) -> Result<Vec<PathBuf>, &'static str> {
    let mut base = if Path::new(pattern).is_absolute() {
        PathBuf::new()
    } else {
        cwd.to_path_buf()
    };
    let mut parts: Vec<String> = Vec::new();
    for component in Path::new(pattern).components() {
        match component {
            Component::Prefix(_) | Component::RootDir => base.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(part) => parts.push(part.to_str().ok_or(ERR_NAME)?.to_owned()),
        }
    }
    let Some(first) = parts.iter().position(|part| has_magic(part)) else {
        return Ok(Vec::new());
    };
    for part in &parts[..first] {
        base.push(part);
    }
    let mut current = vec![base];
    let last = parts.len() - 1;
    for (index, part) in parts.iter().enumerate().skip(first) {
        let dironly = index != last;
        let mut next = Vec::new();
        for directory in &current {
            if part == "**" {
                recursive(directory, dironly, &mut next)?;
            } else if has_magic(part) {
                let keep_hidden = part.starts_with('.');
                for name in names(directory, dironly, keep_hidden, |name| {
                    name_matches(name, part)
                })? {
                    next.push(directory.join(name));
                }
            } else if lexists(&directory.join(part)) {
                next.push(directory.join(part));
            }
        }
        current = next;
    }
    Ok(current)
}

/// `Path(value).expanduser()`.
pub(crate) fn expand_user(value: &str, home: &str) -> Result<PathBuf, &'static str> {
    let path = py_path(value);
    let Some(first) = path.iter().next().and_then(|part| part.to_str()) else {
        return Ok(path);
    };
    if path.is_absolute() || !first.starts_with('~') {
        return Ok(path);
    }
    let home = if first == "~" {
        home.to_owned()
    } else {
        user_home(&first[1..]).unwrap_or_else(|| first.to_owned())
    };
    if home.starts_with('~') {
        return Err(ERR_HOME);
    }
    Ok(path
        .iter()
        .skip(1)
        .fold(PathBuf::from(home), |path, part| path.join(part)))
}

/// `os.path.expanduser("~user")`: the account's home, or `None` when it is
/// unknown (and the `~user` spelling stays).
#[cfg(unix)]
fn user_home(user: &str) -> Option<String> {
    let account = nix::unistd::User::from_name(user).ok()??;
    let dir = account.dir.to_str()?.trim_end_matches('/').to_owned();
    Some(if dir.is_empty() { "/".to_owned() } else { dir })
}

#[cfg(not(unix))]
fn user_home(_user: &str) -> Option<String> {
    None
}

/// `sorted(root.rglob(...))` with `wanted` as the pattern: every entry under `root` at any depth, ordered as `sorted(root.rglob(...))`
/// orders paths; directory links are listed but never descended and
/// unreadable directories are skipped.
pub(crate) fn rglob(
    root: &Path,
    wanted: impl Fn(&str, &Path) -> bool,
) -> Result<Vec<Vec<String>>, &'static str> {
    let mut found: Vec<Vec<String>> = Vec::new();
    let mut pending = vec![(root.to_path_buf(), Vec::<String>::new())];
    while let Some((directory, relative)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let real_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            let raw = entry.file_name();
            let lossy = raw.to_string_lossy().into_owned();
            let keep = wanted(&lossy, &path);
            if !(keep || real_dir) {
                continue;
            }
            let mut parts = relative.clone();
            parts.push(raw.into_string().map_err(|_| ERR_NAME)?);
            if real_dir {
                pending.push((path, parts.clone()));
            }
            if keep {
                found.push(parts);
            }
        }
    }
    found.sort_by_cached_key(|parts| parts.iter().map(|part| sort_key(part)).collect::<Vec<_>>());
    Ok(found)
}
