//! `PackageAuditProjection` — wire contract for the resident op that owns the
//! pure projections of a workspace supply-chain audit: the receipt authority
//! map, bundle advisory-alias enrichment, the CI severity gate, the
//! and the empty-inventory outcome.
//!
//! The caller supplies only what the resident cannot read (the audit result it
//! just assembled). The resident reads the cached advisory bundle from the
//! store itself and hashes workspace files itself.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Capability advertised when the audit projection op exists.
pub const PACKAGE_AUDIT_PROJECTION_FEATURE: &str = "package-audit-projection-v1";
/// Largest request the op accepts (an audit evaluation rides inside it).
pub const PACKAGE_AUDIT_PROJECTION_MAX_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditReceiptQueryV1 {
    /// The audit result payload.
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// Store whose cached bundle resolves advisory aliases; absent for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditAliasesQueryV1 {
    /// `evaluation["packages"]` exactly as assembled (non-objects included).
    pub packages: Vec<Value>,
    pub store_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditCiGateQueryV1 {
    pub evaluation: Value,
    pub threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditEmptyOutcomeQueryV1 {
    pub manifest_paths: Vec<String>,
    pub lockfile_paths: Vec<String>,
    pub posture: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "query", rename_all = "snake_case")]
pub enum PackageAuditQueryV1 {
    Receipt(PackageAuditReceiptQueryV1),
    Aliases(PackageAuditAliasesQueryV1),
    CiGate(PackageAuditCiGateQueryV1),
    EmptyOutcome(PackageAuditEmptyOutcomeQueryV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditProjectionRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub query: PackageAuditQueryV1,
}
