//! The portable Git identity the daemon composes a saved lookup with.
//!
//! `resolve_policy_decision_lookup` (`store_portable_project_memory.py`)
//! reads the workspace's portable identity (`_portable_project_workspace`)
//! and composes the local lookup most restrictive with the lookup under that
//! identity, stripped of any permission it would grant
//! (`_portable_lookup_without_permission_elevation`). The resident derives
//! the identity itself (`project_identity`) and composes it the same way. It
//! reads only when the identity resolves exactly and every row bound to a
//! portable identity is bound to this one; every other store defers.

use super::{HookDirectDefer, StoreShape};
use crate::local_store_read::table_exists;
use crate::mcp_tool_policy_lookup::{most_restrictive, without_permission_elevation};
use crate::project_identity::{resolve, PortableIdentity};
use serde_json::Value;

/// The tables whose rows a lookup reads under a workspace.
const PORTABLE_TABLES: [&str; 2] = ["policy_decisions", "guard_local_once_approvals"];

/// `_portable_project_workspace(workspace)` for the daemon's absolute
/// workspace, once every row bound to a portable identity is bound to it. A
/// local save keys every workspace, so a row under another identity, or any
/// portable row when the workspace has none, came from elsewhere.
pub(super) fn identity(
    store: &StoreShape<'_>,
    workspace: &str,
) -> Result<Option<String>, HookDirectDefer> {
    let identity = match resolve(workspace) {
        PortableIdentity::Absent => None,
        PortableIdentity::Identity(identity) => Some(identity),
        PortableIdentity::Unknown => return Err(HookDirectDefer::SavedDecision),
    };
    for table in PORTABLE_TABLES {
        if !table_exists(store.connection, table).map_err(|_| HookDirectDefer::SavedDecision)? {
            continue;
        }
        let portable = format!("select 1 from {table} where workspace like 'git-project:v1:%'");
        let elsewhere = match identity.as_deref() {
            None => store.any(&format!("{portable} limit 1"), &[])?,
            Some(identity) => store.any(
                &format!("{portable} and workspace <> ?1 limit 1"),
                &[identity],
            )?,
        };
        if elsewhere {
            return Err(HookDirectDefer::SavedDecision);
        }
    }
    Ok(identity)
}

/// The local lookup composed most restrictive with the restrictive-only
/// lookup under the workspace's portable identity.
pub(super) fn compose(local: Value, portable: Value) -> Result<Value, HookDirectDefer> {
    most_restrictive(&[local, without_permission_elevation(portable)])
        .ok_or(HookDirectDefer::SavedDecision)
}

#[cfg(all(test, unix))]
#[path = "hook_direct_saved_portable_tests.rs"]
mod tests;
