//! The portable Git identity the daemon composes a saved lookup with.
//!
//! `resolve_policy_decision_lookup` (`store_portable_project_memory.py`)
//! reads the workspace's portable identity (`_portable_project_workspace`)
//! and composes the local lookup most restrictive with the lookup under that
//! identity, stripped of any permission it would grant
//! (`_portable_lookup_without_permission_elevation`); a workspace that already
//! names the identity reads that lookup alone. The resident derives the
//! identity itself (`project_identity`) and composes it the same way, and
//! reads whenever that identity resolves exactly. A row bound to another
//! project's identity is read by no lookup of this workspace: every workspace
//! selector the lookup binds is this workspace's own.

use super::HookDirectDefer;
use crate::context_digest::python_strip;
use crate::mcp_tool_policy_lookup::{most_restrictive, without_permission_elevation};
use crate::project_identity::{portable_workspace, PortableIdentity};
use serde_json::Value;

/// How the saved lookups of a workspace compose
/// (`resolve_policy_decision_lookup`).
pub(super) enum Composition {
    /// The workspace derives no portable identity, so its own lookup answers.
    Local,
    /// The workspace already names a portable identity
    /// (`_portable_project_workspace`), so that identity's restrictive-only
    /// lookup is the whole answer and no local authority is read beside it.
    Named(String),
    /// The local lookup and the identity's restrictive-only lookup compose
    /// most restrictive.
    Both(String),
}

/// The composition `workspace` names. A workspace whose identity the resident
/// does not resolve exactly defers the hook.
pub(super) fn composition(workspace: &str) -> Result<Composition, HookDirectDefer> {
    match portable_workspace(workspace) {
        PortableIdentity::Absent => Ok(Composition::Local),
        PortableIdentity::Identity(identity) => Ok(if python_strip(workspace) == identity {
            Composition::Named(identity)
        } else {
            Composition::Both(identity)
        }),
        PortableIdentity::Unknown => Err(HookDirectDefer::SavedDecision),
    }
}

/// A portable lookup as the composition reads it: a decision it carries grants
/// no permission the local workspace did not already hold.
pub(super) fn restrictive_only(portable: Value) -> Value {
    without_permission_elevation(portable)
}

pub(super) fn compose(local: Value, portable: Value) -> Result<Value, HookDirectDefer> {
    most_restrictive(&[local, restrictive_only(portable)]).ok_or(HookDirectDefer::SavedDecision)
}

#[cfg(all(test, unix))]
#[path = "hook_direct_saved_portable_tests.rs"]
mod tests;
