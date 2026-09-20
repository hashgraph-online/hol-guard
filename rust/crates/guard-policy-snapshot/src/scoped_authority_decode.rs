//! Explicit presence on the wire: null is valid, an omitted constraint is not.

use super::{
    ManagedAuthority, PolicyAction, PolicyScope, PolicySourceKind, RawAuthority,
    ScopedCommandExpression, ScopedPolicyRow,
};
use crate::managed_configuration::ManagedConfiguration;
use serde::{Deserialize, Deserializer};

fn present_managed_config<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Box<ManagedConfiguration>>, D::Error> {
    ManagedConfiguration::deserialize(decoder).map(|value| Some(Box::new(value)))
}

// An untagged value/unit enum reads a present input value. Unlike Option's
// deserialize_option visitor, it cannot turn a missing field into null.
#[derive(Deserialize)]
#[serde(untagged)]
enum RequiredNullable<T> {
    Value(T),
    Null(()),
}

impl<T> RequiredNullable<T> {
    fn into_option(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Null(()) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireScopedPolicyRow {
    decision_id: u64,
    harness: String,
    scope: PolicyScope,
    action: PolicyAction,
    source_kind: PolicySourceKind,
    updated_at_us: u64,
    artifact_id: RequiredNullable<String>,
    artifact_hash: RequiredNullable<String>,
    workspace: RequiredNullable<String>,
    publisher: RequiredNullable<String>,
    expires_at_ms: RequiredNullable<u64>,
    exact_command_sha256: RequiredNullable<String>,
    requires_exact_context: bool,
}

impl From<WireScopedPolicyRow> for ScopedPolicyRow {
    fn from(row: WireScopedPolicyRow) -> Self {
        Self {
            decision_id: row.decision_id,
            harness: row.harness,
            scope: row.scope,
            action: row.action,
            source_kind: row.source_kind,
            updated_at_us: row.updated_at_us,
            artifact_id: row.artifact_id.into_option(),
            artifact_hash: row.artifact_hash.into_option(),
            workspace: row.workspace.into_option(),
            publisher: row.publisher.into_option(),
            expires_at_ms: row.expires_at_ms.into_option(),
            exact_command_sha256: row.exact_command_sha256.into_option(),
            requires_exact_context: row.requires_exact_context,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireAuthority {
    schema: String,
    generic_precedence: String,
    rows: Vec<ScopedPolicyRow>,
    managed: RequiredNullable<ManagedAuthority>,
    #[serde(default)]
    command_expressions: Vec<ScopedCommandExpression>,
    #[serde(default, deserialize_with = "present_managed_config")]
    managed_config: Option<Box<ManagedConfiguration>>,
}

impl From<WireAuthority> for RawAuthority {
    fn from(authority: WireAuthority) -> Self {
        Self {
            schema: authority.schema,
            generic_precedence: authority.generic_precedence,
            rows: authority.rows,
            managed: authority.managed.into_option(),
            command_expressions: authority.command_expressions,
            managed_config: authority.managed_config,
        }
    }
}
