//! `pathlib.PurePosixPath` / `os.path.realpath` semantics on `/`-separated strings.
//!
//! The identity proofs bind exact path spellings, so paths stay strings and
//! every helper mirrors the CPython call it replaces. A path that cannot be
//! resolved is `None`, never a guess. On Windows the spelling helpers and the
//! resolvers come from `fs_path_windows`; the rest is shared.

#[cfg(not(windows))]
use std::collections::HashMap;
#[cfg(not(windows))]
use std::path::Path;

#[cfg(windows)]
pub(super) use super::fs_path_windows::{
    expand_tilde, is_abs, is_anchored, is_literal, is_sep, join, name, norm, parent, resolve,
    resolve_strict,
};

#[cfg(not(windows))]
const MAX_SYMLINK_DEPTH: usize = 64;

#[cfg(not(windows))]
pub(super) fn is_abs(path: &str) -> bool {
    path.starts_with('/')
}

/// Has a root of its own, so it never names a path below another.
#[cfg(not(windows))]
pub(super) fn is_anchored(path: &str) -> bool {
    is_abs(path)
}

#[cfg(not(windows))]
pub(super) fn is_sep(character: char) -> bool {
    character == '/'
}

/// `str(PurePosixPath(path))`: collapse empty and `.` components.
#[cfg(not(windows))]
pub(super) fn norm(path: &str) -> String {
    let leading = path.bytes().take_while(|byte| *byte == b'/').count();
    let parts: Vec<&str> = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let root = match leading {
        0 => "",
        2 => "//",
        _ => "/",
    };
    if parts.is_empty() {
        return if root.is_empty() {
            ".".to_owned()
        } else {
            root.to_owned()
        };
    }
    format!("{root}{}", parts.join("/"))
}

/// `base / rel`: an absolute `rel` replaces the base.
#[cfg(not(windows))]
pub(super) fn join(base: &str, rel: &str) -> String {
    if is_abs(rel) {
        norm(rel)
    } else if rel.is_empty() {
        norm(base)
    } else {
        norm(&format!("{base}/{rel}"))
    }
}

/// `Path.name`.
#[cfg(not(windows))]
pub(super) fn name(path: &str) -> String {
    let normalized = norm(path);
    if normalized == "." || normalized.bytes().all(|byte| byte == b'/') {
        return String::new();
    }
    normalized.rsplit('/').next().unwrap_or("").to_owned()
}

/// `Path.parent`.
#[cfg(not(windows))]
pub(super) fn parent(path: &str) -> String {
    let normalized = norm(path);
    match normalized.rfind('/') {
        None => ".".to_owned(),
        Some(index) => {
            let head = normalized[..index].trim_end_matches('/');
            if head.is_empty() {
                if normalized.starts_with("//") && index == 1 {
                    "//".to_owned()
                } else {
                    "/".to_owned()
                }
            } else {
                head.to_owned()
            }
        }
    }
}

/// `Path.parents` (nearest first).
pub(super) fn parents(path: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut current = norm(path);
    loop {
        let next = parent(&current);
        if next == current {
            return found;
        }
        found.push(next.clone());
        current = next;
    }
}

/// `path.is_relative_to(root)` for normalized absolute paths.
pub(super) fn is_inside(path: &str, root: &str) -> bool {
    path == root || parents(path).iter().any(|ancestor| ancestor == root)
}

/// A relative path is never probed: on Windows the process cwd and per-drive
/// state would decide what it names.
#[cfg(windows)]
fn is_probe(path: &str) -> bool {
    is_abs(path)
}

#[cfg(not(windows))]
fn is_probe(_path: &str) -> bool {
    true
}

pub(super) fn is_dir(path: &str) -> bool {
    is_probe(path) && std::fs::metadata(path).is_ok_and(|meta| meta.is_dir())
}

pub(super) fn is_file(path: &str) -> bool {
    is_probe(path) && std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// `Path(path).resolve(strict=True)`.
#[cfg(not(windows))]
pub(super) fn resolve_strict(path: &str) -> Option<String> {
    if !is_abs(path) {
        return None;
    }
    std::fs::canonicalize(Path::new(path))
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

/// `Path(path).resolve()` (`os.path.realpath`, non-strict): symlinks of the
/// existing prefix are followed and a missing tail is kept lexically.
#[cfg(not(windows))]
pub(super) fn resolve(path: &str) -> Option<String> {
    if !is_abs(path) {
        return None;
    }
    let mut seen = HashMap::new();
    let (resolved, _) = join_real("/".to_owned(), path.trim_start_matches('/'), &mut seen, 0)?;
    Some(resolved)
}

/// `posixpath.split(path)[0]` for the non-root cases `join_real` produces.
#[cfg(not(windows))]
fn split_head(path: &str) -> (String, String) {
    let cut = path.rfind('/').map_or(0, |index| index + 1);
    let (head, tail) = path.split_at(cut);
    let head = if !head.is_empty() && head.bytes().any(|byte| byte != b'/') {
        head.trim_end_matches('/')
    } else {
        head
    };
    (head.to_owned(), tail.to_owned())
}

#[cfg(not(windows))]
type Seen = HashMap<String, Option<String>>;

/// `posixpath._joinrealpath(path, rest, strict=False, seen)`.
#[cfg(not(windows))]
fn join_real(
    mut path: String,
    rest: &str,
    seen: &mut Seen,
    depth: usize,
) -> Option<(String, bool)> {
    if depth > MAX_SYMLINK_DEPTH {
        return None;
    }
    let mut rest = rest.to_owned();
    if rest.starts_with('/') {
        rest = rest.trim_start_matches('/').to_owned();
        path = "/".to_owned();
    }
    while !rest.is_empty() {
        let (component, remainder) = match rest.split_once('/') {
            Some((head, tail)) => (head.to_owned(), tail.to_owned()),
            None => (rest.clone(), String::new()),
        };
        rest = remainder;
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            if path.is_empty() {
                path = "..".to_owned();
            } else {
                let (head, tail) = split_head(&path);
                path = if tail == ".." {
                    format!("{head}/../..")
                } else {
                    head
                };
            }
            continue;
        }
        let candidate = if path.is_empty() {
            component.clone()
        } else if path.ends_with('/') {
            format!("{path}{component}")
        } else {
            format!("{path}/{component}")
        };
        let is_link =
            std::fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.file_type().is_symlink());
        if !is_link {
            path = candidate;
            continue;
        }
        if let Some(known) = seen.get(&candidate) {
            if let Some(resolved) = known {
                path = resolved.clone();
                continue;
            }
            return Some((format!("{candidate}/{rest}"), false));
        }
        seen.insert(candidate.clone(), None);
        let target = std::fs::read_link(&candidate)
            .ok()?
            .into_os_string()
            .into_string()
            .ok()?;
        let (resolved, ok) = join_real(path.clone(), &target, seen, depth + 1)?;
        if !ok {
            return Some((format!("{resolved}/{rest}"), false));
        }
        path = resolved.clone();
        seen.insert(candidate, Some(resolved));
    }
    Some((path, true))
}

/// `expand_home(value, home)` for a `~`-prefixed argument: only `~/` is expanded.
#[cfg(not(windows))]
pub(super) fn expand_tilde(value: &str, home: &str) -> String {
    match value.strip_prefix("~/") {
        Some(rest) => join(home, rest),
        None => value.to_owned(),
    }
}

/// Lowercase hex SHA-256 of `bytes` (`hashlib.sha256(...).hexdigest()`).
pub(super) use crate::guard_store_wfcap_frame::sha256_hex;

/// Read a file of at most `limit` bytes; a longer one (even if it grew after a
/// size check) is `None`, so a read never exceeds the budget.
pub(super) fn read_bounded(path: &str, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    if !is_probe(path) {
        return None;
    }
    let mut data = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit.saturating_add(1))
        .read_to_end(&mut data)
        .ok()?;
    (data.len() as u64 <= limit).then_some(data)
}
