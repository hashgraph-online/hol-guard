//! Whether a sensitive-named file reached by a content search is a tracked
//! fixture rather than a secret: the repository's own index lists it, it is a
//! small regular file outside every credential-store directory, and Guard's
//! secret detector finds no credential-shaped value in it. Untracked and
//! ignored files, links, and anything unreadable keep the review.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 256 * 1024;
/// Content one walk may read and scan across all of its fixtures.
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ANCESTORS: usize = 64;
const STORE_DIRECTORIES: &[&str] = &[
    ".aws", ".ssh", ".gnupg", ".kube", ".docker", ".azure", ".gcloud", ".config", ".npm",
];

#[derive(Default)]
pub(super) struct TrackedFiles {
    indexes: HashMap<PathBuf, Option<HashSet<Vec<u8>>>>,
    spent: u64,
}

impl TrackedFiles {
    pub(super) fn non_secret(&mut self, path: &Path) -> bool {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return false;
        }
        let Some(repository) = path
            .ancestors()
            .skip(1)
            .take(MAX_ANCESTORS)
            .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
        else {
            return false;
        };
        let Ok(relative) = path.strip_prefix(repository) else {
            return false;
        };
        let in_store = relative.parent().is_some_and(|parent| {
            parent.components().any(|part| {
                part.as_os_str().to_str().is_none_or(|part| {
                    STORE_DIRECTORIES.contains(&part.to_ascii_lowercase().as_str())
                })
            }) || guard_secure_fs::credential_named_path(parent)
        });
        if in_store || guard_secure_fs::credential_named_path(repository) {
            return false;
        }
        let Some(rendered) = relative
            .components()
            .map(|part| part.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join("/").into_bytes())
        else {
            return false;
        };
        let tracked = self
            .indexes
            .entry(repository.to_path_buf())
            .or_insert_with(|| read_index(repository))
            .as_ref()
            .is_some_and(|names| names.contains(&rendered));
        if !tracked {
            return false;
        }
        // Past the budget the scope stays unproven and the search is reviewed.
        self.spent += metadata.len();
        if self.spent > MAX_TOTAL_BYTES {
            return false;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        let text = String::from_utf8_lossy(&bytes);
        // The real name can make the detector stricter (`.env`) but also more
        // lenient (tests/, docs/); both readings must be clean.
        let name = String::from_utf8_lossy(&rendered);
        ["", name.as_ref()].iter().all(|label| {
            guard_scanner::secret_detection::scan_secret_text(&text, label, "search", None, 1)
                .findings
                .is_empty()
        })
    }
}

/// The index of the repository at `directory`, or a linked worktree's own.
fn read_index(directory: &Path) -> Option<HashSet<Vec<u8>>> {
    let dot_git = directory.join(".git");
    let git_dir = if std::fs::symlink_metadata(&dot_git).ok()?.is_dir() {
        dot_git
    } else {
        let text = std::fs::read_to_string(&dot_git).ok()?;
        let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
        let target = Path::new(target);
        if target.is_absolute() {
            target.to_path_buf()
        } else {
            directory.join(target)
        }
    };
    let index = git_dir.join("index");
    let metadata = std::fs::symlink_metadata(&index).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_INDEX_BYTES {
        return None;
    }
    parse_index(&std::fs::read(index).ok()?)
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Entry paths of a version 2, 3 or 4 index. Anything else is unproven.
fn parse_index(bytes: &[u8]) -> Option<HashSet<Vec<u8>>> {
    if bytes.get(..4)? != b"DIRC" {
        return None;
    }
    let version = be32(bytes, 4)?;
    let count = be32(bytes, 8)? as usize;
    if !(2..=4).contains(&version) || count > bytes.len() {
        return None;
    }
    let mut names = HashSet::with_capacity(count);
    let mut at = 12_usize;
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let flags = u16::from_be_bytes(bytes.get(at + 60..at + 62)?.try_into().ok()?);
        let mut fixed = 62;
        if version >= 3 && flags & 0x4000 != 0 {
            fixed += 2;
        }
        let name_at = at + fixed;
        if version == 4 {
            let mut strip = 0_usize;
            let mut cursor = name_at;
            loop {
                let byte = *bytes.get(cursor)?;
                cursor += 1;
                strip = (strip << 7) | usize::from(byte & 0x7f);
                if byte & 0x80 == 0 {
                    break;
                }
                strip = strip.checked_add(1)?;
            }
            let end = cursor + bytes.get(cursor..)?.iter().position(|byte| *byte == 0)?;
            previous.truncate(previous.len().checked_sub(strip)?);
            previous.extend_from_slice(&bytes[cursor..end]);
            names.insert(previous.clone());
            at = end + 1;
        } else {
            let end = name_at + bytes.get(name_at..)?.iter().position(|byte| *byte == 0)?;
            names.insert(bytes[name_at..end].to_vec());
            at += (fixed + (end - name_at) + 8) & !7;
        }
    }
    Some(names)
}
