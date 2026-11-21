//! `ExtensionControl` `preview` query — wire contract for the semantic preview
//! of an extension-control authority mutation.
//!
//! The request carries the catalog the mutation is reviewed against (the
//! packaged catalog or a prepared candidate), the current layers and the
//! proposed layers. The reply describes the effective consequences of the
//! mutation: per changed local target, its explicit and effective states and
//! the permissions, rules and extensions it alone changes. Field order is the
//! order the dashboard renders and digests, so it is part of the contract.

use serde::{Deserialize, Serialize};

/// `schema_version` of the preview the reply carries.
pub const EXTENSION_CONTROL_SEMANTIC_PREVIEW_SCHEMA: &str =
    "guard.daemon.extension-control-semantic-preview.v1";

/// One extension of the catalog a preview is computed against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewExtensionV1 {
    pub extension_id: String,
    pub name: String,
    /// Alternate ids that resolve to this extension, exactly as listed.
    pub aliases: Vec<String>,
    pub dependencies: Vec<String>,
    /// Ids of the rules this extension ships, in catalog order.
    pub rule_ids: Vec<String>,
}

/// One permission of the catalog a preview is computed against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewPermissionV1 {
    pub permission_id: String,
    pub extension_id: String,
    pub label: String,
    pub risk_tier: String,
    pub baseline_floor: String,
    pub rule_ids: Vec<String>,
    pub dependencies: Vec<String>,
    pub conflicts: Vec<String>,
    pub implied_permissions: Vec<String>,
}

/// The catalog projection a preview runs against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewRegistryV1 {
    pub catalog_digest: String,
    pub extensions: Vec<ExtensionControlPreviewExtensionV1>,
    pub permissions: Vec<ExtensionControlPreviewPermissionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewLockdownV1 {
    pub before: bool,
    pub after: bool,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewTargetRefV1 {
    /// `extension` or `permission`.
    pub kind: String,
    pub target_id: String,
}

/// One advisory about a changed target. `target_id` is present for a
/// conflicting permission, `count` for indirectly affected permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewWarningV1 {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    pub message: String,
}

/// One changed local target the catalog knows. `baseline_risk` and
/// `baseline_floor` are present for permission targets; `extension_name` for a
/// permission target whose owning extension the catalog knows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewChangedTargetV1 {
    pub target: ExtensionControlPreviewTargetRefV1,
    pub extension_id: String,
    pub label: String,
    pub before_explicit: String,
    pub after_explicit: String,
    pub before_effective: String,
    pub after_effective: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_risk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_floor: Option<String>,
    pub affected_permission_ids: Vec<String>,
    pub affected_rule_ids: Vec<String>,
    pub affected_extension_ids: Vec<String>,
    pub dependency_permission_ids: Vec<String>,
    pub implied_permission_ids: Vec<String>,
    pub conflict_permission_ids: Vec<String>,
    pub provenance: Vec<String>,
    pub warnings: Vec<ExtensionControlPreviewWarningV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlPreviewSummaryV1 {
    pub newly_blocked_permissions: u64,
    pub newly_allowed_permissions: u64,
    pub effective_change_count: u64,
}

/// The semantic preview of one mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlSemanticPreviewV1 {
    pub schema_version: String,
    pub global_lockdown: ExtensionControlPreviewLockdownV1,
    pub changed_target_count: u64,
    pub affected_permission_count: u64,
    pub affected_rule_count: u64,
    pub changed_targets: Vec<ExtensionControlPreviewChangedTargetV1>,
    pub approval_required: bool,
    pub summary: ExtensionControlPreviewSummaryV1,
}
