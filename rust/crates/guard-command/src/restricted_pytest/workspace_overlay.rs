//! Applies a Linux workspace-sandbox run's overlay upper directory.
//!
//! The command wrote only to the upper layer. Before anything reaches the
//! workspace, every change is checked against the denials the macOS profile
//! enforces in the kernel: Git execution configuration at any depth, agent
//! and editor configuration, the repository's helper paths and credentials.
//! Deleting or replacing a directory changes every path below it, so those
//! are checked too. One denied change discards the whole run, which matches
//! a command that fails on its first denied write.

use super::credentials::patterns;
use super::profiles::workspace_profile::{
    bare_head_pattern, git_exec_pattern, protected_patterns, ref_store_repository_pattern,
};
use super::workspace_linked::LinkedGit;
use super::*;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{File, FileTimes, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};

pub(crate) const WRITE_DENIED_REASON_CODE: &str = "workspace_contained_write_denied";
/// Entries checked across the upper layer and every removed directory.
const MAX_ENTRIES: usize = 500_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    workspace: PathBuf,
    upper: PathBuf,
    write_denials: Vec<PathBuf>,
    /// A linked worktree's shared Git directory and its overlay upper layer.
    #[serde(default)]
    linked_git: Option<LinkedGit>,
    #[serde(default)]
    shared_upper: Option<PathBuf>,
    /// Added to every request by the Python bridge; unused here.
    #[serde(default, rename = "search_path")]
    _search_path: String,
}

fn invalid() -> RestrictedPytestError {
    RestrictedPytestError::new(
        PYTEST_INVALID_COMMAND_REASON_CODE,
        "Invalid workspace sandbox request.",
    )
}

fn denied() -> RestrictedPytestError {
    RestrictedPytestError::new(
        WRITE_DENIED_REASON_CODE,
        "The command changed a protected path, so none of its changes were applied.",
    )
}

fn failed() -> RestrictedPytestError {
    RestrictedPytestError::new(
        WRITE_DENIED_REASON_CODE,
        "The command's changes could not be applied to the workspace.",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Whiteout,
    /// A directory whose lower contents are hidden or that has no lower.
    NewDirectory,
    /// A directory copied up only to hold changed children.
    Directory,
    File,
    Symlink,
}

struct Change {
    relative: PathBuf,
    kind: Kind,
}

struct Denials {
    patterns: Vec<Regex>,
    prefixes: Vec<PathBuf>,
    /// Any `HEAD` but the repository's own, which checkout rewrites, and its
    /// reflog, which every commit appends to.
    head: Regex,
    own_heads: Vec<PathBuf>,
    /// When set, the only paths a change may touch.
    only: Option<Regex>,
}

fn compiled(sources: &[String]) -> Result<Vec<Regex>, RestrictedPytestError> {
    sources
        .iter()
        .map(|source| Regex::new(source).map_err(|_| invalid()))
        .collect()
}

impl Denials {
    fn new(workspace: &Path, prefixes: &[PathBuf]) -> Result<Self, RestrictedPytestError> {
        let mut sources = vec![
            git_exec_pattern(workspace)?,
            ref_store_repository_pattern(workspace)?,
        ];
        sources.extend(protected_patterns(workspace)?);
        sources.extend(patterns());
        Ok(Self {
            patterns: compiled(&sources)?,
            prefixes: prefixes.to_vec(),
            head: Regex::new(&bare_head_pattern(workspace)?).map_err(|_| invalid())?,
            own_heads: vec![
                workspace.join(".git/HEAD"),
                workspace.join(".git/logs/HEAD"),
            ],
            only: None,
        })
    }

    /// A linked worktree's run may change only its paths in the shared
    /// directory, and no bare repository planted beside a ref store `HEAD`.
    fn shared(linked: &LinkedGit) -> Result<Self, RestrictedPytestError> {
        Ok(Self {
            patterns: compiled(&linked.denial_patterns()?)?,
            prefixes: Vec::new(),
            head: Regex::new(&bare_head_pattern(linked.checkout())?).map_err(|_| invalid())?,
            own_heads: linked.heads(),
            only: Some(Regex::new(&linked.overlay_pattern()?).map_err(|_| invalid())?),
        })
    }

    /// A denial, or a directory between the workspace and one: replacing
    /// that directory would redirect the denied path, as the macOS profile
    /// also prevents.
    fn denies(&self, path: &Path) -> bool {
        let text = path.to_string_lossy();
        self.patterns.iter().any(|pattern| pattern.is_match(&text))
            || self
                .prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix) || prefix.starts_with(path))
            || (self.head.is_match(&text) && !self.own_heads.iter().any(|own| path == own))
            || self.only.as_ref().is_some_and(|only| !only.is_match(&text))
    }
}

/// An overlay private attribute on `path`, without following a symlink.
#[cfg(target_os = "linux")]
fn overlay_attribute(path: &Path, name: &str) -> Option<Vec<u8>> {
    for namespace in ["user", "trusted"] {
        let attribute = format!("{namespace}.overlay.{name}");
        let mut value = [0u8; 16];
        match rustix::fs::lgetxattr(path, attribute.as_str(), &mut value[..]) {
            Ok(length) => return Some(value[..length].to_vec()),
            // Too long to read here still means the attribute is present.
            Err(rustix::io::Errno::RANGE) => return Some(Vec::new()),
            Err(_) => {}
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn overlay_attribute(_path: &Path, _name: &str) -> Option<Vec<u8>> {
    None
}

/// Every entry in the upper layer, parents before children. Fails on an
/// entry this overlay should never produce: a device, socket or FIFO, a
/// redirect, metacopy or attribute whiteout, or an unknown opaque value.
fn changes(upper: &Path, workspace: &Path) -> Result<Vec<Change>, RestrictedPytestError> {
    let mut result = Vec::new();
    // Below a new or opaque directory the kernel never reads the lower
    // layer, so a lower directory at the same path says nothing.
    let mut pending = vec![(PathBuf::new(), false)];
    while let Some((relative, replaced)) = pending.pop() {
        let entries: Vec<_> = fs::read_dir(upper.join(&relative))
            .map_err(|_| failed())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<_, _>>()
            .map_err(|_| failed())?;
        for name in entries {
            let relative = relative.join(name);
            let path = upper.join(&relative);
            let metadata = path.symlink_metadata().map_err(|_| failed())?;
            let file_type = metadata.file_type();
            if ["redirect", "metacopy", "whiteout"]
                .iter()
                .any(|attribute| overlay_attribute(&path, attribute).is_some())
            {
                return Err(failed());
            }
            let kind = if file_type.is_char_device() && metadata.rdev() == 0 {
                Kind::Whiteout
            } else if file_type.is_dir() {
                let lower_dir = workspace
                    .join(&relative)
                    .symlink_metadata()
                    .is_ok_and(|lower| lower.is_dir());
                match overlay_attribute(&path, "opaque").as_deref() {
                    Some(b"y") => Kind::NewDirectory,
                    Some(_) => return Err(failed()),
                    None if lower_dir && !replaced => Kind::Directory,
                    None => Kind::NewDirectory,
                }
            } else if file_type.is_file() {
                Kind::File
            } else if file_type.is_symlink() {
                Kind::Symlink
            } else {
                return Err(denied());
            };
            if file_type.is_dir() {
                pending.push((relative.clone(), kind == Kind::NewDirectory));
            }
            result.push(Change { relative, kind });
            if result.len() > MAX_ENTRIES {
                return Err(failed());
            }
        }
    }
    // Paths compare by component, so each parent sorts before its children.
    result.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(result)
}

/// Whether any path at or below a lower directory is denied. Removing or
/// replacing the directory changes each of them.
fn removal_denied(
    root: &Path,
    denials: &Denials,
    budget: &mut usize,
) -> Result<bool, RestrictedPytestError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| failed())? {
            let entry = entry.map_err(|_| failed())?;
            *budget = budget.checked_sub(1).ok_or_else(failed)?;
            let path = entry.path();
            if denials.denies(&path) {
                return Ok(true);
            }
            if entry.file_type().map_err(|_| failed())?.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(false)
}

fn validate(
    changes: &[Change],
    workspace: &Path,
    denials: &Denials,
) -> Result<(), RestrictedPytestError> {
    let mut budget = MAX_ENTRIES;
    for change in changes {
        let target = workspace.join(&change.relative);
        if change.kind == Kind::Directory {
            continue;
        }
        if denials.denies(&target) {
            return Err(denied());
        }
        let lower_dir = target.symlink_metadata().is_ok_and(|lower| lower.is_dir());
        if lower_dir && removal_denied(&target, denials, &mut budget)? {
            return Err(denied());
        }
    }
    Ok(())
}

/// Remove whatever is at `target` without following a symlink.
fn remove(target: &Path) -> Result<(), RestrictedPytestError> {
    match target.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(target).map_err(|_| failed()),
        Ok(_) => fs::remove_file(target).map_err(|_| failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(failed()),
    }
}

/// Create a fresh sibling of `target` with `create`, which must fail when
/// the name exists, so no existing entry is ever replaced by the staging.
fn stage(
    target: &Path,
    create: impl Fn(&Path) -> std::io::Result<()>,
) -> Result<PathBuf, RestrictedPytestError> {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let parent = target.parent().ok_or_else(failed)?;
    for _ in 0..64 {
        let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staging = parent.join(format!(".hol-guard-{}-{index}", std::process::id()));
        match create(&staging) {
            Ok(()) => return Ok(staging),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(failed()),
        }
    }
    Err(failed())
}

/// Move a staged entry over `target`, removing a directory there first.
fn commit(staging: &Path, target: &Path) -> Result<(), RestrictedPytestError> {
    if target.symlink_metadata().is_ok_and(|lower| lower.is_dir()) {
        if let Err(error) = remove(target) {
            let _ = fs::remove_file(staging);
            return Err(error);
        }
    }
    fs::rename(staging, target).map_err(|_| {
        let _ = fs::remove_file(staging);
        failed()
    })
}

fn copy_file(source: &Path, target: &Path) -> Result<(), RestrictedPytestError> {
    let metadata = source.symlink_metadata().map_err(|_| failed())?;
    let staging = stage(target, |path| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)?;
        let written = std::io::copy(&mut File::open(source)?, &mut output)
            .and_then(|_| {
                output.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o777))
            })
            .and_then(|_| output.set_times(FileTimes::new().set_modified(metadata.modified()?)));
        if let Err(error) = written {
            let _ = fs::remove_file(path);
            // Any failure after creation must not read as a name collision.
            return Err(std::io::Error::other(error));
        }
        Ok(())
    })?;
    commit(&staging, target)
}

fn copy_symlink(source: &Path, target: &Path) -> Result<(), RestrictedPytestError> {
    let destination = fs::read_link(source).map_err(|_| failed())?;
    let staging = stage(target, |path| {
        std::os::unix::fs::symlink(&destination, path)
    })?;
    commit(&staging, target)
}

fn apply_change(
    change: &Change,
    upper: &Path,
    workspace: &Path,
) -> Result<(), RestrictedPytestError> {
    let source = upper.join(&change.relative);
    let target = workspace.join(&change.relative);
    // Each parent is an earlier change that left a real directory.
    let parent_real = target
        .parent()
        .and_then(|parent| parent.symlink_metadata().ok())
        .is_some_and(|parent| parent.is_dir());
    if !parent_real {
        return Err(failed());
    }
    match change.kind {
        Kind::Whiteout => remove(&target),
        Kind::Directory => target
            .symlink_metadata()
            .ok()
            .filter(|metadata| metadata.is_dir())
            .map(|_| ())
            .ok_or_else(failed),
        Kind::NewDirectory => {
            remove(&target)?;
            let mode = source.symlink_metadata().map_err(|_| failed())?.mode() & 0o777;
            fs::DirBuilder::new()
                .mode(mode | 0o700)
                .create(&target)
                .map_err(|_| failed())
        }
        Kind::File => copy_file(&source, &target),
        Kind::Symlink => copy_symlink(&source, &target),
    }
}

/// Check every change in `upper`, then apply them all to `workspace`.
/// Returns how many entries changed.
#[cfg(test)]
pub(crate) fn apply(
    upper: &Path,
    workspace: &Path,
    write_denials: &[PathBuf],
) -> Result<usize, RestrictedPytestError> {
    apply_linked(upper, workspace, write_denials, None)
}

/// [`apply`], and for a linked worktree also `shared`'s upper layer to its
/// shared Git directory. Both layers are checked before either is applied.
pub(crate) fn apply_linked(
    upper: &Path,
    workspace: &Path,
    write_denials: &[PathBuf],
    shared: Option<(&LinkedGit, &Path)>,
) -> Result<usize, RestrictedPytestError> {
    let mut layers = vec![(upper, workspace, Denials::new(workspace, write_denials)?)];
    if let Some((linked, shared_upper)) = shared {
        layers.push((shared_upper, &linked.common, Denials::shared(linked)?));
    }
    let mut checked = Vec::new();
    for (upper, root, denials) in &layers {
        let changes = changes(upper, root)?;
        validate(&changes, root, denials)?;
        checked.push(changes);
    }
    let mut count = 0;
    for ((upper, root, _), changes) in layers.iter().zip(&checked) {
        count += apply_checked(upper, root, changes)?;
    }
    Ok(count)
}

fn apply_checked(
    upper: &Path,
    workspace: &Path,
    changes: &[Change],
) -> Result<usize, RestrictedPytestError> {
    for change in changes {
        apply_change(change, upper, workspace)?;
    }
    // New directories were writable while their children were applied.
    // Existing directories keep their mode, since the check skips them.
    for change in changes.iter().rev() {
        if change.kind == Kind::NewDirectory {
            let source = upper.join(&change.relative).symlink_metadata();
            let mode = source.map_err(|_| failed())?.mode() & 0o777;
            fs::set_permissions(
                workspace.join(&change.relative),
                fs::Permissions::from_mode(mode),
            )
            .map_err(|_| failed())?;
        }
    }
    Ok(changes.len())
}

/// Whether the probe's run left the changes a working overlay records: a new
/// file, a whiteout for a deleted file, and an opaque replacement directory.
pub(crate) fn probe_changes(upper: &Path) -> Option<bool> {
    let changes = changes(upper, Path::new("/nonexistent-hol-guard-probe")).ok()?;
    let kind = |name: &str| {
        changes
            .iter()
            .find(|change| change.relative == Path::new(name))
            .map(|change| change.kind)
    };
    Some(
        kind("new") == Some(Kind::File)
            && kind("gone") == Some(Kind::Whiteout)
            && kind("d") == Some(Kind::NewDirectory)
            && overlay_attribute(&upper.join("d"), "opaque").as_deref() == Some(b"y"),
    )
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if operation != "apply_workspace_overlay" {
        return None;
    }
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| invalid())
        .and_then(|input| {
            if !input.workspace.is_absolute()
                || !input.upper.is_absolute()
                || input.upper.starts_with(&input.workspace)
                || input.workspace.starts_with(&input.upper)
            {
                return Err(invalid());
            }
            let shared = match (&input.linked_git, &input.shared_upper) {
                (None, None) => None,
                (Some(linked), Some(upper)) => Some((
                    linked.with_layers(&input.workspace, &[upper], &[&input.upper])?,
                    upper.as_path(),
                )),
                _ => return Err(invalid()),
            };
            apply_linked(&input.upper, &input.workspace, &input.write_denials, shared)
        });
    Some(match result {
        Ok(count) => json!({"value": {"applied": count}}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

#[cfg(test)]
#[path = "workspace_overlay_tests.rs"]
mod tests;
