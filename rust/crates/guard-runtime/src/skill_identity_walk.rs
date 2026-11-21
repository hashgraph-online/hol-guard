//! Bounded, race-aware walk of one skill directory tree.
//!
//! Every filesystem fact is captured together with a full stat identity so the
//! hashing pass can prove the tree it hashed is the tree it listed.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};

use guard_contracts::SkillDirectoryLimitsV1;

use crate::skill_identity_canon::{canonical_component, casefold, Failure};

use crate::skill_identity_platform::{
    directory_guard, link_loop, unsupported_reparse, DirectoryGuard,
};
pub(crate) use crate::skill_identity_platform::{security_mode, stat_key, StatKey};

/// `lstat` with the identity-specific error mapping: a vanished path means the
/// tree changed under us; anything else is unreadable.
pub(crate) fn safe_lstat(path: &Path) -> Result<Metadata, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => Failure::TreeChangedDuringHash,
        _ => Failure::UnreadableEntry,
    })?;
    if unsupported_reparse(&metadata) {
        return Err(Failure::UnsupportedReparsePoint);
    }
    Ok(metadata)
}

/// Canonicalize an existing path, naming the failure the way identity callers
/// report it: a missing target is `broken`, a link cycle is `symlink_loop`.
pub(crate) fn resolve_existing(path: &Path, broken: Failure) -> Result<PathBuf, Failure> {
    fs::canonicalize(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            broken
        } else if link_loop(&error) {
            Failure::SymlinkLoop
        } else {
            Failure::UnreadableEntry
        }
    })
}

pub(crate) fn is_directory(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

/// Lexical (no filesystem access) absolute normalization: `.` and `..` are
/// collapsed textually, matching `os.path.abspath` for absolute inputs.
pub(crate) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
            Component::CurDir => {}
        }
    }
    normalized
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryType {
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Clone)]
pub(crate) struct TreeEntry {
    pub(crate) path: PathBuf,
    pub(crate) relative_path: String,
    pub(crate) entry_type: EntryType,
    pub(crate) key: StatKey,
    pub(crate) raw_link_target: Option<String>,
}

/// Order-independent snapshot used to detect structural change between passes.
pub(crate) type Structure = Vec<(String, EntryType, StatKey, Option<String>)>;

/// Children of `path` in descending raw-name order. Readdir order is a
/// property of the filesystem (hash order on ext4 and APFS), and the hashing
/// pass stops at the first unsupported entry, so an unordered walk would
/// account different bytes for the same tree on different machines. The
/// original vectors were recorded in an order this reproduces.
///
/// Only the first `remaining + 1` children in that order are kept. The walk
/// fails with `MaxEntriesExceeded` no later than that last kept child, so a
/// later one is never visited, while the kept ones still go through the
/// per-entry depth, name and collision checks in walk order: a directory with
/// more children than the budget reports the same failure it would if every
/// name were buffered, and holds at most twice the budget while reading.
fn read_children(path: &Path, remaining: u64) -> Result<std::vec::IntoIter<fs::DirEntry>, Failure> {
    let directory = fs::read_dir(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => Failure::TreeChangedDuringHash,
        _ => Failure::UnreadableEntry,
    })?;
    let keep = usize::try_from(remaining)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let mut children = Vec::new();
    for child in directory {
        let child = child.map_err(|_| Failure::UnreadableEntry)?;
        children.push((Reverse(child.file_name()), child));
        if children.len() >= keep.saturating_mul(2) {
            children.sort_by(|left, right| left.0.cmp(&right.0));
            children.truncate(keep);
        }
    }
    children.sort_by(|left, right| left.0.cmp(&right.0));
    children.truncate(keep);
    Ok(children
        .into_iter()
        .map(|(_, child)| child)
        .collect::<Vec<_>>()
        .into_iter())
}

struct Frame {
    children: std::vec::IntoIter<fs::DirEntry>,
    parts: Vec<String>,
    _guard: DirectoryGuard,
}

#[derive(Default)]
struct Seen {
    normalized: HashSet<String>,
    folded: HashMap<String, String>,
}

impl Seen {
    fn admit(&mut self, relative_path: &str) -> Result<(), Failure> {
        if self.normalized.contains(relative_path) {
            return Err(Failure::DuplicatePath);
        }
        let folded = casefold(relative_path);
        if let Some(prior) = self.folded.get(&folded) {
            if prior != relative_path {
                return Err(Failure::CaseCollision);
            }
        }
        self.normalized.insert(relative_path.to_owned());
        self.folded.insert(folded, relative_path.to_owned());
        Ok(())
    }
}

fn classify(path: &Path) -> Result<(EntryType, StatKey, Option<String>), Failure> {
    let metadata = safe_lstat(path)?;
    let file_type = metadata.file_type();
    let (entry_type, raw_target) = if file_type.is_symlink() {
        let target = fs::read_link(path).map_err(|_| Failure::TreeChangedDuringHash)?;
        let text = target
            .as_os_str()
            .to_str()
            .ok_or(Failure::InvalidPathEncoding)?;
        (EntryType::Symlink, Some(text.to_owned()))
    } else if file_type.is_dir() {
        (EntryType::Directory, None)
    } else if file_type.is_file() {
        (EntryType::File, None)
    } else {
        return Err(Failure::SpecialFile);
    };
    Ok((entry_type, stat_key(path, &metadata)?, raw_target))
}

/// Walk `root` depth first in descending name order, capturing every entry.
/// Directory contents are visited immediately after their directory entry, so
/// the order matches the order the hashing pass accounts bytes in.
pub(crate) fn collect_entries(
    root: &Path,
    limits: &SkillDirectoryLimitsV1,
) -> Result<(Vec<TreeEntry>, Structure), Failure> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen = Seen::default();
    let mut stack = vec![Frame {
        children: read_children(root, limits.max_entries)?,
        parts: Vec::new(),
        _guard: directory_guard(root)?,
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(child) = frame.children.next() else {
            stack.pop();
            continue;
        };
        let canonical_name = canonical_component(child.file_name().as_os_str())?;
        let mut parts = frame.parts.clone();
        parts.push(canonical_name);
        let relative_path = parts.join("/");
        seen.admit(&relative_path)?;
        if parts.len() as u64 > limits.max_depth {
            return Err(Failure::MaxDepthExceeded);
        }
        if entries.len() as u64 >= limits.max_entries {
            return Err(Failure::MaxEntriesExceeded);
        }
        let path = child.path();
        let (entry_type, key, raw_link_target) = classify(&path)?;
        let descend = entry_type == EntryType::Directory;
        entries.push(TreeEntry {
            path: path.clone(),
            relative_path,
            entry_type,
            key,
            raw_link_target,
        });
        if descend {
            stack.push(Frame {
                children: read_children(
                    &path,
                    limits.max_entries.saturating_sub(entries.len() as u64),
                )?,
                parts,
                _guard: directory_guard(&path)?,
            });
        }
    }
    let mut structure: Structure = entries
        .iter()
        .map(|entry| {
            (
                entry.relative_path.clone(),
                entry.entry_type,
                entry.key,
                entry.raw_link_target.clone(),
            )
        })
        .collect();
    structure.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    Ok((entries, structure))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_rejects_duplicates_and_case_collisions() {
        let mut seen = Seen::default();
        seen.admit("dir/Stra\u{df}e.txt").unwrap();
        assert_eq!(
            seen.admit("dir/Stra\u{df}e.txt"),
            Err(Failure::DuplicatePath)
        );
        assert_eq!(seen.admit("dir/STRASSE.txt"), Err(Failure::CaseCollision));
        seen.admit("dir/other.txt").unwrap();
    }

    #[test]
    fn collect_entries_order_does_not_follow_creation_order() {
        let limits = SkillDirectoryLimitsV1 {
            max_depth: 8,
            max_entries: 16,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
        };
        let expected = ["z.txt", "sub", "sub/b.txt", "sub/a.txt", "a.txt"];
        for names in [
            ["a.txt", "sub", "sub/a.txt", "sub/b.txt", "z.txt"],
            ["z.txt", "sub", "sub/b.txt", "sub/a.txt", "a.txt"],
        ] {
            let root = tempfile::tempdir().unwrap();
            for name in names {
                if name == "sub" {
                    fs::create_dir(root.path().join(name)).unwrap();
                } else {
                    fs::write(root.path().join(name), b"x").unwrap();
                }
            }
            let (entries, _) = collect_entries(root.path(), &limits).unwrap();
            let order: Vec<_> = entries.iter().map(|e| e.relative_path.as_str()).collect();
            assert_eq!(order, expected);
        }
    }

    #[test]
    fn a_directory_past_the_entry_budget_keeps_the_per_entry_failure_order() {
        // `sub` sits at the depth limit and holds more children than the
        // budget has left. The first child it would visit is too deep, so the
        // walk reports that, as it would if every name were buffered.
        let limits = SkillDirectoryLimitsV1 {
            max_depth: 1,
            max_entries: 2,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
        };
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(root.path().join("sub").join(name), b"x").unwrap();
        }
        assert_eq!(
            collect_entries(root.path(), &limits).unwrap_err(),
            Failure::MaxDepthExceeded
        );
    }

    #[test]
    fn lexical_normalize_collapses_dot_segments() {
        assert_eq!(
            lexical_normalize(Path::new("/a/./b/../c//d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(lexical_normalize(Path::new("/../..")), PathBuf::from("/"));
    }
}
