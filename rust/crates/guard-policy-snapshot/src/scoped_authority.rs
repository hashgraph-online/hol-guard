//! Bounded compilation values; possession of a value is not runtime proof.
//!
//! A consumer must authenticate the containing versioned snapshot and derive
//! its own trusted request facts. V3 snapshots cannot contain this value.

use crate::managed_configuration::ManagedConfiguration;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

#[path = "scoped_authority_decode.rs"]
mod decoding;

#[path = "scoped_authority_match.rs"]
mod matching;

#[path = "scoped_command_expression.rs"]
mod command_bindings;
pub use command_bindings::ScopedCommandExpression;
pub use matching::{ExactPolicyContextInputs, PolicyIdentityInputs, ScopedPolicyRequest};

pub const AUTHORITY_SCHEMA: &str = "guard-native-policy-authority.v1";
pub const SCOPED_AUTHORITY_FEATURE: &str = "policy-scoped-authority-v1";
pub const MANAGED_AUTHORITY_FEATURE: &str = "policy-managed-authority-v1";
pub const AUTHORITY_MAX_ROWS: usize = 256;
pub const AUTHORITY_MAX_CONTROLS: usize = 512;
pub const AUTHORITY_MAX_BYTES: usize = 192 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_EXACT_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("native_policy_authority_encoding_invalid")]
    Encoding,
    #[error("native_policy_authority_schema_invalid")]
    Schema,
    #[error("native_policy_authority_text_invalid")]
    Text,
    #[error("native_policy_authority_integer_invalid")]
    Integer,
    #[error("native_policy_authority_scope_invalid")]
    Scope,
    #[error("native_policy_authority_exact_context_invalid")]
    ExactContext,
    #[error("native_policy_authority_exact_command_invalid")]
    ExactCommand,
    #[error("native_policy_authority_row_limit")]
    RowLimit,
    #[error("native_policy_authority_row_duplicate")]
    RowDuplicate,
    #[error("native_policy_authority_control_invalid")]
    Control,
    #[error("native_policy_authority_control_duplicate")]
    ControlDuplicate,
    #[error("native_policy_authority_catalog_invalid")]
    Catalog,
    #[error("native_policy_authority_command_expression_invalid")]
    CommandExpression,
    #[error("native_policy_authority_byte_limit")]
    ByteLimit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyScope {
    Artifact,
    Workspace,
    Publisher,
    Harness,
    Global,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyAction {
    Allow,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PolicySourceKind {
    Local,
    SignedBundle,
    SignedMemory,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "decoding::WireScopedPolicyRow")]
pub struct ScopedPolicyRow {
    decision_id: u64,
    harness: String,
    scope: PolicyScope,
    action: PolicyAction,
    source_kind: PolicySourceKind,
    updated_at_us: u64,
    artifact_id: Option<String>,
    artifact_hash: Option<String>,
    workspace: Option<String>,
    publisher: Option<String>,
    expires_at_ms: Option<u64>,
    exact_command_sha256: Option<String>,
    requires_exact_context: bool,
}

impl fmt::Debug for ScopedPolicyRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopedPolicyRow { .. }")
    }
}

impl ScopedPolicyRow {
    pub fn decision_id(&self) -> u64 {
        self.decision_id
    }

    pub fn action(&self) -> PolicyAction {
        self.action
    }

    pub fn scope(&self) -> PolicyScope {
        self.scope
    }

    pub fn source_kind(&self) -> PolicySourceKind {
        self.source_kind
    }

    pub fn exact_command_sha256(&self) -> Option<&str> {
        self.exact_command_sha256.as_deref()
    }

    pub fn artifact_hash(&self) -> Option<&str> {
        self.artifact_hash.as_deref()
    }

    fn expects_exact_context(&self) -> bool {
        self.source_kind == PolicySourceKind::Local
            && matches!(self.scope, PolicyScope::Harness | PolicyScope::Global)
            && self.artifact_id.as_deref().is_some_and(|artifact| {
                matches!(
                    artifact.strip_prefix("family:"),
                    Some("file-read" | "mcp-tool" | "package-request" | "prompt" | "tool-action")
                )
            })
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        integer(self.decision_id, true)?;
        integer(self.updated_at_us, false)?;
        if let Some(expiry) = self.expires_at_ms {
            integer(expiry, false)?;
        }
        text(&self.harness)?;
        for selector in [
            &self.artifact_id,
            &self.artifact_hash,
            &self.workspace,
            &self.publisher,
        ]
        .into_iter()
        .flatten()
        {
            text(selector)?;
        }
        let valid_scope = match self.scope {
            PolicyScope::Artifact => {
                self.artifact_id.is_some() && self.workspace.is_none() && self.publisher.is_none()
            }
            PolicyScope::Workspace => self.workspace.is_some() && self.publisher.is_none(),
            PolicyScope::Publisher => {
                self.publisher.is_some() && self.workspace.is_none() && self.artifact_id.is_none()
            }
            PolicyScope::Harness | PolicyScope::Global => {
                self.workspace.is_none()
                    && self.publisher.is_none()
                    && self
                        .artifact_id
                        .as_deref()
                        .is_none_or(|value| value.starts_with("family:"))
            }
        };
        if !valid_scope {
            return Err(AuthorityError::Scope);
        }
        if self.requires_exact_context != self.expects_exact_context() {
            return Err(AuthorityError::ExactContext);
        }
        if self.exact_command_sha256.as_deref().is_some_and(|digest| {
            !super::valid_hex(digest, 64)
                || self.artifact_id.is_none()
                || !matches!(self.scope, PolicyScope::Artifact | PolicyScope::Workspace)
        }) {
            return Err(AuthorityError::ExactCommand);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ControlTargetKind {
    Extension,
    Permission,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ControlState {
    Enabled,
    Disabled,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedControl {
    target_kind: ControlTargetKind,
    target_id: String,
    state: ControlState,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedAuthority {
    revision: u64,
    managed_revision: u64,
    catalog_digest: String,
    global_lockdown: bool,
    controls: Vec<ManagedControl>,
}

impl fmt::Debug for ManagedAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedAuthority { .. }")
    }
}

impl ManagedControl {
    pub fn target_kind(&self) -> ControlTargetKind {
        self.target_kind
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
}

impl ManagedAuthority {
    pub fn global_lockdown(&self) -> bool {
        self.global_lockdown
    }
    pub fn controls(&self) -> &[ManagedControl] {
        &self.controls
    }
    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        integer(self.revision, false)?;
        integer(self.managed_revision, false)?;
        if !super::valid_hex(&self.catalog_digest, 64) {
            return Err(AuthorityError::Catalog);
        }
        if self.controls.len() > AUTHORITY_MAX_CONTROLS {
            return Err(AuthorityError::Control);
        }
        let mut identities = BTreeSet::new();
        for control in &self.controls {
            text(&control.target_id)?;
            let valid_target = control.target_id.starts_with("command.")
                && control.target_id.split(['.', '-']).all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                });
            if !valid_target
                || ((control.target_kind == ControlTargetKind::Permission)
                    != control.target_id.contains(".permission."))
            {
                return Err(AuthorityError::Control);
            }
            if !identities.insert((control.target_kind, &control.target_id)) {
                return Err(AuthorityError::ControlDuplicate);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "decoding::WireAuthority")]
struct RawAuthority {
    schema: String,
    generic_precedence: String,
    rows: Vec<ScopedPolicyRow>,
    managed: Option<ManagedAuthority>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    command_expressions: Vec<ScopedCommandExpression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_config: Option<Box<ManagedConfiguration>>,
}

/// Only validated authority can be deserialized into this wrapper. A snapshot
/// verifier still must authenticate it; this type creates no trust by itself.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct NativePolicyAuthority(RawAuthority);

impl fmt::Debug for NativePolicyAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePolicyAuthority")
            .field("row_count", &self.0.rows.len())
            .field("has_managed_controls", &self.0.managed.is_some())
            .finish()
    }
}

impl<'de> Deserialize<'de> for NativePolicyAuthority {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let authority = Self(RawAuthority::deserialize(deserializer)?);
        authority.validate().map_err(serde::de::Error::custom)?;
        Ok(authority)
    }
}

impl NativePolicyAuthority {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() > AUTHORITY_MAX_BYTES {
            return Err(AuthorityError::ByteLimit);
        }
        serde_json::from_slice(bytes).map_err(|_| AuthorityError::Encoding)
    }

    pub fn rows(&self) -> &[ScopedPolicyRow] {
        &self.0.rows
    }

    pub fn managed(&self) -> Option<&ManagedAuthority> {
        self.0.managed.as_ref()
    }

    pub fn managed_config(&self) -> Option<&ManagedConfiguration> {
        self.0.managed_config.as_deref()
    }

    /// True only when no scoped condition or independently composed origin
    /// remains. The containing snapshot still requires full authentication.
    pub fn is_defaults_only(&self) -> bool {
        let RawAuthority {
            schema: _,
            generic_precedence: _,
            rows,
            managed,
            command_expressions,
            managed_config,
        } = &self.0;
        rows.is_empty()
            && managed.is_none()
            && command_expressions.is_empty()
            && managed_config.is_none()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        let value = serde_json::to_value(self).map_err(|_| AuthorityError::Encoding)?;
        let bytes = super::canonical_json_bytes(&value).map_err(|_| AuthorityError::Encoding)?;
        if bytes.len() > AUTHORITY_MAX_BYTES {
            return Err(AuthorityError::ByteLimit);
        }
        Ok(bytes)
    }

    /// Content identity only; it is never an authentication or application ACK.
    pub fn content_digest(&self) -> Result<String, AuthorityError> {
        Ok(super::digest_bytes(&self.canonical_bytes()?))
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        if self.0.schema != AUTHORITY_SCHEMA
            || self.0.generic_precedence != "specificity-recency.v1"
        {
            return Err(AuthorityError::Schema);
        }
        if self.0.rows.len() > AUTHORITY_MAX_ROWS {
            return Err(AuthorityError::RowLimit);
        }
        let mut identities = BTreeSet::new();
        for row in &self.0.rows {
            row.validate()?;
            if !identities.insert(row.decision_id) {
                return Err(AuthorityError::RowDuplicate);
            }
        }
        command_bindings::validate_bindings(self)?;
        if let Some(managed) = &self.0.managed {
            managed.validate()?;
        }
        self.canonical_bytes()?;
        Ok(())
    }
}

fn integer(value: u64, positive: bool) -> Result<(), AuthorityError> {
    if value > MAX_EXACT_INTEGER || (positive && value == 0) {
        Err(AuthorityError::Integer)
    } else {
        Ok(())
    }
}

fn text(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value != value.trim()
        || value.contains('\0')
        || value.len() > MAX_TEXT_BYTES
    {
        Err(AuthorityError::Text)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "scoped_authority_tests.rs"]
mod tests;
