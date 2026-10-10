//! Bounded, race-aware walk of one skill directory tree.
//!
//! Every filesystem fact is captured together with a full stat identity so the
//! hashing pass can prove the tree it hashed is the tree it listed.

use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use guard_contracts::SkillDirectoryLimitsV1;

use crate::skill_identity_canon::{canonical_component, casefold, Failure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StatKey {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

pub(crate) fn stat_key(metadata: &Metadata) -> StatKey {
    StatKey {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        size: metadata.size(),
        mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
        ctime_ns: i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
    }
}

/// `lstat` with the identity-specific error mapping: a vanished path means the
/// tree changed under us; anything else is unreadable.
pub(crate) fn safe_lstat(path: &Path) -> Result<Metadata, Failure> {
    fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => Failure::TreeChangedDuringHash,
        _ => Failure::UnreadableEntry,
    })
}

pub(crate) fn security_mode(metadata: &Metadata) -> String {
    format!("{:04o}", metadata.mode() & 0o7777)
}

/// Canonicalize an existing path, naming the failure the way identity callers
/// report it: a missing target is `broken`, a link cycle is `symlink_loop`.
pub(crate) fn resolve_existing(path: &Path, broken: Failure) -> Result<PathBuf, Failure> {
    fs::canonicalize(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            broken
        } else if error.raw_os_error() == Some(libc::ELOOP) {
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
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
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

fn open_directory(path: &Path) -> Result<fs::ReadDir, Failure> {
    fs::read_dir(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => Failure::TreeChangedDuringHash,
        _ => Failure::UnreadableEntry,
    })
}

struct Frame {
    children: fs::ReadDir,
    parts: Vec<String>,
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
    Ok((entry_type, stat_key(&metadata), raw_target))
}

/// Walk `root` depth first, capturing every entry. Directory contents are
/// visited immediately after their directory entry, so the order matches the
/// order the hashing pass accounts bytes in.
pub(crate) fn collect_entries(
    root: &Path,
    limits: &SkillDirectoryLimitsV1,
) -> Result<(Vec<TreeEntry>, Structure), Failure> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen = Seen::default();
    let mut stack = vec![Frame {
        children: open_directory(root)?,
        parts: Vec::new(),
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(next) = frame.children.next() else {
            stack.pop();
            continue;
        };
        let child = next.map_err(|_| Failure::UnreadableEntry)?;
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
                children: open_directory(&path)?,
                parts,
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
    fn lexical_normalize_collapses_dot_segments() {
        assert_eq!(
            lexical_normalize(Path::new("/a/./b/../c//d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(lexical_normalize(Path::new("/../..")), PathBuf::from("/"));
    }
}
