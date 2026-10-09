//! Bounded, fail-closed discovery of primary skill documents.
//!
//! Discovery never follows links and stops descending once a directory holds
//! `SKILL.md`; the identity inspector owns that complete subtree. Every
//! unreadable, linked, or over-budget grouping path becomes a typed issue
//! carrying its own incomplete identity, so no unknown content is silently
//! omitted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use guard_contracts::{SkillDirectoryLimitsV1, SkillDiscoveryIssueV1, SkillDiscoveryV1};
use sha2::{Digest, Sha256};

use crate::skill_identity_canon::{canonical_component, Failure};
use crate::skill_identity_inspect::incomplete_identity;
use crate::skill_identity_walk::is_directory;

const PRIMARY_NAME: &str = "SKILL.md";

type IssueKey = (Vec<u8>, &'static str);

struct Issues {
    found: BTreeMap<IssueKey, Failure>,
}

impl Issues {
    fn record(&mut self, relative: &[u8], reason: Failure) {
        let relative = if relative.is_empty() { b"." } else { relative };
        self.found
            .insert((relative.to_vec(), reason.as_str()), reason);
    }
}

fn join_relative(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        name.to_vec()
    } else {
        let mut joined = parent.to_vec();
        joined.push(b'/');
        joined.extend_from_slice(name);
        joined
    }
}

/// Stable per-issue identifier: SHA-256 over `relative\0reason`, truncated.
pub(crate) fn issue_id(relative: &[u8], reason: Failure) -> String {
    issue_id_for_label(relative, reason.as_str())
}

/// Issue identifier keyed by the reason's wire spelling. Also pins the
/// constant the Python transport reports when no runtime answers.
pub(crate) fn issue_id_for_label(relative: &[u8], reason: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(relative);
    digest.update([0_u8]);
    digest.update(reason.as_bytes());
    hex::encode(digest.finalize())[..16].to_owned()
}

fn linked_directory_failure(path: &Path) -> Failure {
    match fs::canonicalize(path) {
        Ok(resolved) if is_directory(&resolved) => Failure::SymlinkDirectoryUnsupported,
        Ok(_) => Failure::RootNotDirectory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Failure::SymlinkBroken,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Failure::SymlinkLoop,
        Err(_) => Failure::UnreadableEntry,
    }
}

fn into_payload(documents: BTreeSet<Vec<u8>>, issues: Issues) -> SkillDiscoveryV1 {
    // Sorted by (relative path, reason) so the output is deterministic.
    let issues = issues
        .found
        .into_iter()
        .map(|((relative, _), reason)| SkillDiscoveryIssueV1 {
            relative_path_hex: hex::encode(&relative),
            failure_reason: reason,
            issue_id: issue_id(&relative, reason),
            identity: incomplete_identity(reason, None, 0, 0),
        })
        .collect();
    SkillDiscoveryV1 {
        documents_hex: documents.iter().map(hex::encode).collect(),
        issues,
    }
}

pub(crate) fn discover_skill_documents(
    root: &Path,
    limits: &SkillDirectoryLimitsV1,
) -> SkillDiscoveryV1 {
    let mut issues = Issues {
        found: BTreeMap::new(),
    };
    let mut documents: BTreeSet<Vec<u8>> = BTreeSet::new();
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => issues.record(b"", Failure::UnreadableEntry),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            issues.record(b"", linked_directory_failure(root));
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            issues.record(b"", Failure::RootNotDirectory);
        }
        Ok(_) => walk(root, limits, &mut documents, &mut issues),
    }
    into_payload(documents, issues)
}

fn walk(
    root: &Path,
    limits: &SkillDirectoryLimitsV1,
    documents: &mut BTreeSet<Vec<u8>>,
    issues: &mut Issues,
) {
    let mut pending: Vec<(PathBuf, Vec<u8>, usize)> = vec![(root.to_path_buf(), Vec::new(), 0)];
    let mut visited: u64 = 0;
    'directories: while let Some((directory, relative, depth)) = pending.pop() {
        let primary_relative = join_relative(&relative, PRIMARY_NAME.as_bytes());
        match fs::symlink_metadata(directory.join(PRIMARY_NAME)) {
            Ok(_) => {
                documents.insert(primary_relative);
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                issues.record(&primary_relative, Failure::UnreadableEntry);
                continue;
            }
        }
        let children = match fs::read_dir(&directory) {
            Ok(children) => children,
            Err(_) => {
                issues.record(&relative, Failure::UnreadableEntry);
                continue;
            }
        };
        for child in children {
            let Ok(child) = child else {
                issues.record(&relative, Failure::UnreadableEntry);
                break;
            };
            if visited >= limits.max_entries {
                issues.record(b"", Failure::MaxEntriesExceeded);
                break 'directories;
            }
            visited += 1;
            let name = child.file_name();
            let child_relative = join_relative(&relative, name.as_bytes());
            if let Err(reason) = canonical_component(&name) {
                issues.record(&child_relative, reason);
                continue;
            }
            let path = child.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                issues.record(&child_relative, Failure::UnreadableEntry);
                continue;
            };
            if metadata.file_type().is_symlink() {
                issues.record(&child_relative, linked_directory_failure(&path));
                continue;
            }
            if !metadata.file_type().is_dir() {
                continue;
            }
            if (depth + 1) as u64 > limits.max_depth {
                issues.record(&child_relative, Failure::MaxDepthExceeded);
                continue;
            }
            pending.push((path, child_relative, depth + 1));
        }
    }
}
