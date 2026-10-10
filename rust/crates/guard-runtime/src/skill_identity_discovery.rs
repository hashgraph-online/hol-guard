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

/// Wire budget for one discovery reply, well inside the resident's response
/// ceiling so the framed envelope can never push a valid answer over it.
const REPLY_BUDGET_BYTES: usize = 1_536 * 1_024;

fn issue_record(relative: &[u8], reason: Failure) -> SkillDiscoveryIssueV1 {
    SkillDiscoveryIssueV1 {
        relative_path_hex: hex::encode(relative),
        failure_reason: reason,
        issue_id: issue_id(relative, reason),
        identity: incomplete_identity(reason, None, 0, 0),
    }
}

fn wire_len(issue: &SkillDiscoveryIssueV1) -> usize {
    serde_json::to_vec(issue).map_or(usize::MAX, |encoded| encoded.len() + 1)
}

/// Builds the reply inside [`REPLY_BUDGET_BYTES`]. Anything that does not fit
/// is dropped, never the whole answer: a single `max_entries_exceeded` issue
/// for the root records that the listing is incomplete, so the omitted scope
/// stays visible and non-reusable instead of vanishing.
fn into_payload(documents: BTreeSet<Vec<u8>>, issues: Issues) -> SkillDiscoveryV1 {
    let truncation = issue_record(b".", Failure::MaxEntriesExceeded);
    let mut remaining = REPLY_BUDGET_BYTES.saturating_sub(wire_len(&truncation));
    let mut truncated = false;
    let mut documents_hex = Vec::new();
    for document in &documents {
        let cost = document.len() * 2 + 3;
        if cost > remaining {
            truncated = true;
            break;
        }
        remaining -= cost;
        documents_hex.push(hex::encode(document));
    }
    let mut kept: Vec<SkillDiscoveryIssueV1> = Vec::new();
    for ((relative, _), reason) in issues.found {
        let issue = issue_record(&relative, reason);
        let cost = wire_len(&issue);
        if cost > remaining {
            truncated = true;
            break;
        }
        remaining -= cost;
        kept.push(issue);
    }
    if truncated
        && !kept.iter().any(|issue| {
            issue.relative_path_hex == truncation.relative_path_hex
                && issue.failure_reason == truncation.failure_reason
        })
    {
        kept.push(truncation);
    }
    // Hex preserves byte order, so this matches the (path, reason) ordering.
    kept.sort_by(|left, right| {
        (&left.relative_path_hex, left.failure_reason.as_str())
            .cmp(&(&right.relative_path_hex, right.failure_reason.as_str()))
    });
    SkillDiscoveryV1 {
        documents_hex,
        issues: kept,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn oversized(count: usize) -> BTreeSet<Vec<u8>> {
        (0..count)
            .map(|index| {
                let mut name = format!("{index:05}-").into_bytes();
                name.resize(220, b'x');
                name.extend_from_slice(b"/SKILL.md");
                name
            })
            .collect()
    }

    #[test]
    fn oversized_document_list_is_truncated_with_an_explicit_issue() {
        let payload = into_payload(
            oversized(4_000),
            Issues {
                found: BTreeMap::new(),
            },
        );
        let encoded = crate::resident_protocol::encode_response(&payload).unwrap();
        assert!(encoded.len() <= crate::MAX_NATIVE_RESPONSE_BYTES);
        assert!(!payload.documents_hex.is_empty());
        assert!(payload.documents_hex.len() < 4_000);
        assert_eq!(payload.issues.len(), 1);
        assert_eq!(payload.issues[0].relative_path_hex, hex::encode(b"."));
        assert_eq!(
            payload.issues[0].failure_reason,
            Failure::MaxEntriesExceeded
        );
    }

    #[test]
    fn oversized_issue_list_keeps_a_single_truncation_issue() {
        let mut issues = Issues {
            found: BTreeMap::new(),
        };
        for index in 0..4_000 {
            let mut name = format!("{index:05}-").into_bytes();
            name.resize(220, b'x');
            issues.record(&name, Failure::SymlinkBroken);
        }
        let payload = into_payload(BTreeSet::new(), issues);
        let encoded = crate::resident_protocol::encode_response(&payload).unwrap();
        assert!(encoded.len() <= crate::MAX_NATIVE_RESPONSE_BYTES);
        let truncations = payload
            .issues
            .iter()
            .filter(|issue| issue.failure_reason == Failure::MaxEntriesExceeded)
            .count();
        assert_eq!(truncations, 1);
        let keys: Vec<_> = payload
            .issues
            .iter()
            .map(|issue| {
                (
                    issue.relative_path_hex.clone(),
                    issue.failure_reason.as_str(),
                )
            })
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn small_reply_is_untouched() {
        let payload = into_payload(
            oversized(3),
            Issues {
                found: BTreeMap::new(),
            },
        );
        assert_eq!(payload.documents_hex.len(), 3);
        assert!(payload.issues.is_empty());
    }
}
