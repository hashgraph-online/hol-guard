//! `pathlib.PureWindowsPath` / `ntpath.realpath` semantics on `\`- or
//! `/`-separated strings.
//!
//! Paths stay strings, rendered with `\` the way `str(WindowsPath)` is. Only a
//! drive-rooted path is absolute. A drive-relative (`C:x`) or rooted (`\x`)
//! spelling depends on per-drive state the request does not carry, a UNC path
//! would make Guard itself reach a remote host, and a device or verbatim path
//! that Win32 would not normalize the same way names a different object; none
//! of them resolves. Neither does a component Windows opens as something other
//! than its spelling: a stream (`name:s`), a trailing dot or space, a device
//! name or a wildcard. `.` and `..` fold lexically, as Win32 folds them before
//! the filesystem sees the path. Python accepted all of these spellings; the
//! proofs refuse them, so such an action stays a one-time decision.

use std::path::Path;

/// The anchor a path is resolved against.
#[derive(Clone, Copy, PartialEq)]
enum Root {
    Relative,
    Drive(u8),
    /// Drive-relative, rooted, UNC, device or non-disk verbatim.
    Unpinned,
}

pub(super) fn is_sep(character: char) -> bool {
    character == '\\' || character == '/'
}

fn parse(path: &str) -> (Root, Vec<&str>) {
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        return verbatim(rest);
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return match path[2..].starts_with(is_sep) {
            true => (
                Root::Drive(bytes[0].to_ascii_uppercase()),
                split(&path[2..]),
            ),
            false => (Root::Unpinned, Vec::new()),
        };
    }
    if path.starts_with(is_sep) {
        return (Root::Unpinned, Vec::new());
    }
    (Root::Relative, split(path))
}

/// `\\?\C:\...`: Win32 neither splits `/` nor folds `.` and `..` here, so only
/// a disk path of plain components means the same without the prefix.
fn verbatim(rest: &str) -> (Root, Vec<&str>) {
    let bytes = rest.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
        return (Root::Unpinned, Vec::new());
    }
    let tail = &rest[3..];
    let parts: Vec<&str> = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split('\\').collect()
    };
    if parts
        .iter()
        .any(|part| part.is_empty() || matches!(*part, "." | "..") || part.contains('/'))
    {
        return (Root::Unpinned, Vec::new());
    }
    (Root::Drive(bytes[0].to_ascii_uppercase()), parts)
}

fn split(text: &str) -> Vec<&str> {
    text.split(is_sep).filter(|part| !part.is_empty()).collect()
}

/// Fold `.` and `..`; `..` never climbs above a drive root.
fn fold(root: Root, parts: Vec<&str>) -> Vec<&str> {
    let mut folded: Vec<&str> = Vec::new();
    for part in parts {
        match part {
            "." => {}
            ".." if root != Root::Relative => {
                folded.pop();
            }
            ".." if folded.last().is_some_and(|last| *last != "..") => {
                folded.pop();
            }
            _ => folded.push(part),
        }
    }
    folded
}

fn render(root: Root, parts: &[&str]) -> String {
    match root {
        Root::Drive(letter) => format!("{}:\\{}", letter as char, parts.join("\\")),
        _ if parts.is_empty() => ".".to_owned(),
        _ => parts.join("\\"),
    }
}

/// `CON`, `NUL`, `COM1`, ... open a device whatever directory or extension
/// follows them.
fn is_device_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut characters = stem.chars();
    let prefix: String = characters.by_ref().take(3).collect();
    let rest: Vec<char> = characters.collect();
    ["COM", "LPT"].contains(&prefix.to_ascii_uppercase().as_str())
        && rest.len() == 1
        && (rest[0].is_ascii_digit() || matches!(rest[0], '¹' | '²' | '³'))
}

/// A component Windows opens exactly as spelled.
fn is_plain(part: &str) -> bool {
    !part.is_empty()
        && !part.ends_with(['.', ' '])
        && !part
            .chars()
            .any(|character| character < ' ' || "<>:\"|?*".contains(character))
        && !is_device_name(part)
}

/// `FOO~1.TXT` may later become the short name of a file spelled otherwise.
fn may_be_short_name(part: &str) -> bool {
    part.split_once('~')
        .is_some_and(|(_, after)| after.starts_with(|c: char| c.is_ascii_digit()))
}

pub(super) fn is_abs(path: &str) -> bool {
    matches!(parse(path).0, Root::Drive(_))
}

/// Has a drive or root of its own, so it never names a path below another.
pub(super) fn is_anchored(path: &str) -> bool {
    parse(path).0 != Root::Relative
}

/// A drive-rooted path that compares as text against another one: no
/// `\\?\` prefix and no component that folds (`.`, `..`), that Windows
/// trims or that may be a short name.
pub(super) fn is_literal(path: &str) -> bool {
    let (Root::Drive(_), parts) = parse(path) else {
        return false;
    };
    !path.starts_with(r"\\")
        && parts
            .iter()
            .all(|part| is_plain(part) && !may_be_short_name(part))
}

/// `str(PureWindowsPath(path))` with `.` and `..` folded; an unpinned
/// spelling is returned as given, which no resolver accepts.
pub(super) fn norm(path: &str) -> String {
    match parse(path) {
        (Root::Unpinned, _) => path.to_owned(),
        (root, parts) => render(root, &fold(root, parts)),
    }
}

/// `base / rel`: a drive-rooted `rel` replaces the base; an unpinned one is
/// kept as given, so it never resolves under `base`.
pub(super) fn join(base: &str, rel: &str) -> String {
    match parse(rel).0 {
        Root::Drive(_) => norm(rel),
        Root::Unpinned => rel.to_owned(),
        Root::Relative if rel.is_empty() => norm(base),
        Root::Relative => norm(&format!("{base}\\{rel}")),
    }
}

/// `Path.name`.
pub(super) fn name(path: &str) -> String {
    let (root, parts) = parse(path);
    fold(root, parts)
        .last()
        .map_or_else(String::new, |last| (*last).to_owned())
}

/// `Path.parent`; a root, `.` and an unpinned spelling are their own parent.
pub(super) fn parent(path: &str) -> String {
    match parse(path) {
        (Root::Unpinned, _) => path.to_owned(),
        (root, parts) => {
            let mut folded = fold(root, parts);
            folded.pop();
            render(root, &folded)
        }
    }
}

/// The drive-rooted path `canonicalize` returned, without its `\\?\` prefix,
/// when that spelling opens the same file; a UNC or volume path is `None`.
fn plain_canonical(canonical: &Path) -> Option<String> {
    let text = canonical.to_str()?;
    let (root @ Root::Drive(_), parts) = verbatim(text.strip_prefix(r"\\?\")?) else {
        return None;
    };
    parts
        .iter()
        .all(|part| is_plain(part))
        .then(|| render(root, &parts))
}

/// The drive root and folded components of a path every component of which
/// Windows opens as spelled.
fn pinned(path: &str) -> Option<(Root, Vec<&str>)> {
    let (root @ Root::Drive(_), parts) = parse(path) else {
        return None;
    };
    let folded = fold(root, parts);
    folded
        .iter()
        .all(|part| is_plain(part))
        .then_some((root, folded))
}

/// `Path(path).resolve(strict=True)`.
pub(super) fn resolve_strict(path: &str) -> Option<String> {
    let (root, parts) = pinned(path)?;
    plain_canonical(&std::fs::canonicalize(render(root, &parts)).ok()?)
}

fn is_missing(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// `Path(path).resolve()`: the longest existing prefix is canonicalized
/// (following symlinks and junctions) and a missing tail is kept lexically.
/// A prefix that exists but cannot be canonicalized (a dangling link, a
/// denied directory) is `None`, never a lexical guess.
pub(super) fn resolve(path: &str) -> Option<String> {
    let (root, parts) = pinned(path)?;
    for existing in (0..=parts.len()).rev() {
        let prefix = render(root, &parts[..existing]);
        match std::fs::canonicalize(&prefix) {
            Ok(canonical) => {
                let tail = &parts[existing..];
                if tail.iter().any(|part| may_be_short_name(part)) {
                    return None;
                }
                let resolved = plain_canonical(&canonical)?;
                return Some(match tail.is_empty() {
                    true => resolved,
                    false => format!("{}\\{}", resolved.trim_end_matches('\\'), tail.join("\\")),
                });
            }
            Err(_) => match std::fs::symlink_metadata(&prefix) {
                Err(error) if is_missing(&error) => continue,
                _ => return None,
            },
        }
    }
    None
}

/// `expand_home(value, home)`: `~\` and `~/` expand, as `ntpath.expanduser` does.
pub(super) fn expand_tilde(value: &str, home: &str) -> String {
    match value.strip_prefix('~') {
        Some(rest) if rest.starts_with(is_sep) => join(home, &rest[1..]),
        _ => value.to_owned(),
    }
}
