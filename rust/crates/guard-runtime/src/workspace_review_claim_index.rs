#![forbid(unsafe_code)]
//! Immutable replay evidence, committed by a platform-secure root digest.

use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::workspace_review_secure_state::WorkspaceReviewClaimV1;

const NODE_DOMAIN: &[u8] = b"guard-workspace-review-claim-index-node\0";
const KEY_DOMAIN: &[u8] = b"guard-workspace-review-claim-index-key\0";
const MAX_NODE_BYTES: u64 = 2048;
const INVALID: &str = "native_workspace_review_claim_index_invalid";
const UNAVAILABLE: &str = "native_workspace_review_claim_index_unavailable";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimIndexAnchor {
    pub(crate) root: String,
    pub(crate) claim_count: u64,
}

impl ClaimIndexAnchor {
    pub(crate) fn validate(&self) -> bool {
        valid_digest(&self.root) && self.claim_count > 0
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Node {
    Leaf {
        key: String,
        claim: WorkspaceReviewClaimV1,
    },
    Branch {
        prefix: String,
        children: BTreeMap<String, String>,
    },
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64 && valid_hex(value)
}

fn valid_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn key(purpose: &str, digest: &str) -> String {
    let mut bytes = Vec::from(KEY_DOMAIN);
    bytes.extend_from_slice(purpose.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(digest.as_bytes());
    digest_bytes(&bytes)
}

fn node_digest(bytes: &[u8]) -> String {
    let mut framed = Vec::from(NODE_DOMAIN);
    framed.extend_from_slice(bytes);
    digest_bytes(&framed)
}

fn node_path(state_base: &Path, digest: &str, create: bool) -> Result<(PathBuf, PathBuf), String> {
    if !valid_digest(digest) {
        return Err(INVALID.to_owned());
    }
    let private_root = crate::resident_state::private_root_for_state_base(state_base)
        .map_err(|_| UNAVAILABLE.to_owned())?;
    let base =
        crate::resident_state::ensure_private_directory_under(state_base, &private_root, false)
            .map_err(|_| UNAVAILABLE.to_owned())?;
    let directory = crate::resident_state::ensure_private_directory_under(
        &base.join("workspace-review-claims"),
        &private_root,
        create,
    )
    .map_err(|_| UNAVAILABLE.to_owned())?;
    let shard = crate::resident_state::ensure_private_directory_under(
        &directory.join(&digest[..2]),
        &private_root,
        create,
    )
    .map_err(|_| UNAVAILABLE.to_owned())?;
    Ok((shard.join(format!("{digest}.json")), private_root))
}

fn validate_node(node: &Node) -> Result<(), String> {
    let valid = match node {
        Node::Leaf {
            key: stored_key,
            claim,
        } => {
            valid_digest(&claim.claim_id)
                && valid_digest(&claim.envelope_digest)
                && claim
                    .semantic_decision_digest
                    .as_ref()
                    .is_some_and(|digest| valid_digest(digest))
                && claim.expires_at_ms != Some(0)
                && (stored_key == &key("claim", &claim.claim_id)
                    || claim
                        .semantic_decision_digest
                        .as_ref()
                        .is_some_and(|digest| stored_key == &key("semantic", digest)))
        }
        Node::Branch { prefix, children } => {
            prefix.len() < 64
                && valid_hex(prefix)
                && (2..=16).contains(&children.len())
                && children.iter().all(|(edge, digest)| {
                    edge.len() == 1 && valid_hex(edge) && valid_digest(digest)
                })
        }
    };
    if valid {
        Ok(())
    } else {
        Err(INVALID.to_owned())
    }
}

fn read_node(state_base: &Path, digest: &str) -> Result<Node, String> {
    let (path, private_root) = node_path(state_base, digest, false)?;
    let (value, bytes) = super::policy_store_persistence::read_private_json(
        &path,
        MAX_NODE_BYTES,
        "workspace_review_claim",
        &private_root,
    )
    .map_err(|_| UNAVAILABLE.to_owned())?
    .ok_or_else(|| UNAVAILABLE.to_owned())?;
    if node_digest(&bytes) != digest
        || canonical_json_bytes(&value).map_err(|_| INVALID.to_owned())? != bytes
    {
        return Err(INVALID.to_owned());
    }
    let node: Node = serde_json::from_value(value).map_err(|_| INVALID.to_owned())?;
    validate_node(&node)?;
    Ok(node)
}

fn write_node(state_base: &Path, node: &Node) -> Result<String, String> {
    validate_node(node)?;
    let value = serde_json::to_value(node).map_err(|_| INVALID.to_owned())?;
    let bytes = canonical_json_bytes(&value).map_err(|_| INVALID.to_owned())?;
    let digest = node_digest(&bytes);
    let (path, private_root) = node_path(state_base, &digest, true)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            // Reuse only authenticated existing bytes; never repair or
            // overwrite a corrupted immutable object during insertion.
            read_node(state_base, &digest)?;
            return Ok(digest);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(UNAVAILABLE.to_owned()),
    }
    super::policy_store_persistence::persist_private_bytes(
        &path,
        &bytes,
        MAX_NODE_BYTES,
        "workspace_review_claim",
        &private_root,
    )
    .map_err(|_| UNAVAILABLE.to_owned())?;
    Ok(digest)
}

fn node_prefix(node: &Node) -> &str {
    match node {
        Node::Leaf { key, .. } => key,
        Node::Branch { prefix, .. } => prefix,
    }
}

fn common_prefix(left: &str, right: &str) -> usize {
    left.bytes()
        .zip(right.bytes())
        .take_while(|(a, b)| a == b)
        .count()
}

fn lookup(
    state_base: &Path,
    root: &str,
    wanted: &str,
) -> Result<Option<WorkspaceReviewClaimV1>, String> {
    let mut digest = root.to_owned();
    let mut expected_prefix = String::new();
    for _ in 0..=64 {
        let node = read_node(state_base, &digest)?;
        if !node_prefix(&node).starts_with(&expected_prefix) {
            return Err(INVALID.to_owned());
        }
        match node {
            Node::Leaf { key, claim } => return Ok((key == wanted).then_some(claim)),
            Node::Branch { prefix, children } => {
                if !wanted.starts_with(&prefix) {
                    return Ok(None);
                }
                let edge = &wanted[prefix.len()..prefix.len() + 1];
                let Some(child) = children.get(edge) else {
                    return Ok(None);
                };
                expected_prefix = format!("{prefix}{edge}");
                digest = child.clone();
            }
        }
    }
    Err(INVALID.to_owned())
}

fn insert_node(
    state_base: &Path,
    root: Option<&str>,
    leaf: &Node,
    minimum_prefix: usize,
) -> Result<String, String> {
    let Some(root) = root else {
        return write_node(state_base, leaf);
    };
    let node = read_node(state_base, root)?;
    let wanted = node_prefix(leaf);
    let existing = node_prefix(&node);
    let common = common_prefix(wanted, existing);
    if common < minimum_prefix {
        return Err(INVALID.to_owned());
    }
    if common < existing.len() {
        let new_digest = write_node(state_base, leaf)?;
        let children = BTreeMap::from([
            (existing[common..common + 1].to_owned(), root.to_owned()),
            (wanted[common..common + 1].to_owned(), new_digest),
        ]);
        return write_node(
            state_base,
            &Node::Branch {
                prefix: wanted[..common].to_owned(),
                children,
            },
        );
    }
    match node {
        Node::Leaf { .. } => Err("native_workspace_review_decision_replay".to_owned()),
        Node::Branch {
            prefix,
            mut children,
        } => {
            let edge = &wanted[prefix.len()..prefix.len() + 1];
            let next = insert_node(
                state_base,
                children.get(edge).map(String::as_str),
                leaf,
                prefix.len() + 1,
            )?;
            children.insert(edge.to_owned(), next);
            write_node(state_base, &Node::Branch { prefix, children })
        }
    }
}

pub(crate) fn find_claim(
    state_base: &Path,
    anchor: &ClaimIndexAnchor,
    claim_id: &str,
) -> Result<Option<WorkspaceReviewClaimV1>, String> {
    lookup(state_base, &anchor.root, &key("claim", claim_id))
}

pub(crate) fn find_semantic(
    state_base: &Path,
    anchor: &ClaimIndexAnchor,
    semantic_digest: &str,
) -> Result<Option<WorkspaceReviewClaimV1>, String> {
    lookup(state_base, &anchor.root, &key("semantic", semantic_digest))
}

pub(crate) fn insert_claim(
    state_base: &Path,
    root: Option<&str>,
    claim: &WorkspaceReviewClaimV1,
) -> Result<String, String> {
    let semantic = claim
        .semantic_decision_digest
        .as_ref()
        .ok_or_else(|| INVALID.to_owned())?;
    let claim_root = insert_node(
        state_base,
        root,
        &Node::Leaf {
            key: key("claim", &claim.claim_id),
            claim: claim.clone(),
        },
        0,
    )?;
    insert_node(
        state_base,
        Some(&claim_root),
        &Node::Leaf {
            key: key("semantic", semantic),
            claim: claim.clone(),
        },
        0,
    )
}

pub(crate) fn sync_directories_before_commit(state_base: &Path) -> Result<(), String> {
    // Node persistence syncs every shard. Sync the two directory links too,
    // before a secure anchor can make newly created shards authoritative.
    #[cfg(unix)]
    for path in [
        state_base.join("workspace-review-claims"),
        state_base.to_owned(),
    ] {
        std::fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| UNAVAILABLE.to_owned())?;
    }
    #[cfg(not(unix))]
    let _ = state_base;
    Ok(())
}

#[cfg(test)]
#[path = "workspace_review_claim_index_tests.rs"]
mod tests;
