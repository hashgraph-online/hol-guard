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
#[serde(deny_unknown_fields)]
pub struct PackageAuditCloudPayloadQueryV1 {
    pub workspace_dir: String,
    pub workspace_id: String,
    /// Store whose `supply_chain_bundle_summary` sync payload supplies the policy version.
    pub store_path: String,
    /// The inventory is rebuilt here from the same options the caller's
    /// `workspace_inventory` read used, then pinned to the digest that read
    /// reported. A large inventory never crosses the resident request, and a
    /// workspace that changed in between is rejected.
    pub inventory_workspace_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_workspace_dir: Option<String>,
    #[serde(default)]
    pub sbom_paths: Vec<String>,
    #[serde(default)]
    pub include_lockfile_warnings: bool,
    pub inventory_digest: String,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i64>,
    /// Host name the caller read (`socket.gethostname()`); the resident cannot read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditBatchUrlQueryV1 {
    pub sync_url: String,
    pub workspace_id: String,
    /// Present for the job-status URL, absent for the batch URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditCloudNormalizeQueryV1 {
    pub response: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditWorkspaceCandidatesQueryV1 {
    /// `store.list_managed_installs()` exactly as listed.
    pub installs: Vec<Value>,
    /// Explicit workspace to audit first; absent audits managed workspaces only.
    /// With `candidates` false only the ordered managed workspace strings return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    pub candidates: bool,
}

/// One package-protect projection: the resident owns the verdict, receipt and
/// every user-facing surface; the caller supplies the intent, artifact,
/// execution context and evaluation it assembled and persists the result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditProtectProjectionQueryV1 {
    /// Intent identity with exact (unsanitized) target dictionaries.
    pub intent: Value,
    /// `artifact_id`, `name` and `source_scope`.
    pub artifact: Value,
    /// `PackageExecutionContext.to_evidence()` as built for this request.
    pub execution_context: Value,
    pub artifact_hash: String,
    #[serde(default)]
    pub additional_policy_context: Option<Value>,
    pub observe_mode: bool,
    pub invoking_harness: String,
    /// `PackageRequestEvaluation.to_dict()`.
    pub evaluation: Value,
    pub command: Vec<String>,
    /// Absent blocks exactly when the execution policy action is not permitted.
    #[serde(default)]
    pub blocking: Option<bool>,
    pub executed: bool,
    /// True projects the observe-mode execution action; false the observed one.
    pub project_execution_action: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "query", rename_all = "snake_case")]
pub enum PackageAuditQueryV1 {
    CloudPayload(PackageAuditCloudPayloadQueryV1),
    BatchUrl(PackageAuditBatchUrlQueryV1),
    CloudNormalize(PackageAuditCloudNormalizeQueryV1),
    WorkspaceCandidates(PackageAuditWorkspaceCandidatesQueryV1),
    Receipt(PackageAuditReceiptQueryV1),
    Aliases(PackageAuditAliasesQueryV1),
    CiGate(PackageAuditCiGateQueryV1),
    EmptyOutcome(PackageAuditEmptyOutcomeQueryV1),
    ProtectProjection(PackageAuditProtectProjectionQueryV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageAuditProjectionRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub query: PackageAuditQueryV1,
}
