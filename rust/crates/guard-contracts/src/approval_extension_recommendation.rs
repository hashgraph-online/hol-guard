//! Wire contract for the resident approval extension-recommendation op.
//!
//! A pending review may carry a queue-time hint naming the configurable
//! permissions that would let its command run. The recommendation shown with
//! the review is that hint re-checked, on every read, against the active
//! catalog and the current control authority, so stale or no-longer-applicable
//! advice is never offered. It carries catalog identifiers and bounded catalog
//! labels only, never command text.
//!
//! The op is pure: the request carries the hint and the control authority view
//! the caller already holds, and the resident reads the catalog it has
//! admitted. A rejected request is a bound `error` reply with its specific
//! code, never a default verdict.

use serde::{Deserialize, Serialize};

use crate::{ExtensionAllowHintV1, NativeExtensionControlLayerV1};

/// Schema discriminator for the request.
pub const APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA: &str =
    "guard-approval-extension-recommendation-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_EXTENSION_RECOMMENDATION_RESULT_SCHEMA: &str =
    "guard-approval-extension-recommendation-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_EXTENSION_RECOMMENDATION_FEATURE: &str = "approval-extension-recommendation-v1";
/// Schema discriminator of the recommendation itself, as the Inbox reads it.
pub const APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA: &str =
    "guard.approval-extension-recommendation.v1";
/// Query kind that re-checks a hint into a recommendation.
pub const APPROVAL_EXTENSION_RECOMMENDATION_RECOMMEND_KIND: &str = "recommend";
/// Query kind that names which risk classes need a caution.
pub const APPROVAL_EXTENSION_RECOMMENDATION_CAUTION_KIND: &str = "caution_risk_classes";

/// Largest canonical request serialization the op will accept.
pub const APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most risk classes one caution query may ask about.
pub const APPROVAL_EXTENSION_RECOMMENDATION_MAX_RISK_CLASSES: usize = 4096;
/// Most ids any one list of a stored hint may name.
pub const APPROVAL_EXTENSION_RECOMMENDATION_MAX_HINT_IDS: usize = 12;

/// The control authority view a recommendation is judged against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalExtensionRecommendationSnapshotV1 {
    /// Authority health (`protected`, `tampered`, ...); anything but
    /// `protected` makes the recommendation advisory only.
    pub health: String,
    pub revision: u64,
    /// Catalog digest the control authority view is bound to.
    pub catalog_digest: String,
    pub layers: Vec<NativeExtensionControlLayerV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalExtensionRecommendationQueryV1 {
    /// Re-check a queued hint against the active catalog and the controls.
    Recommend {
        hint: Box<ExtensionAllowHintV1>,
        /// Digest of the registry the caller serves; the op answers from its
        /// own admitted catalog only when the two are the same catalog.
        registry_catalog_digest: String,
        snapshot: ApprovalExtensionRecommendationSnapshotV1,
    },
    /// The subset of `risk_classes` that calls for a caution.
    CautionRiskClasses { risk_classes: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalExtensionRecommendationRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    pub query: ApprovalExtensionRecommendationQueryV1,
}

/// One permission the Inbox offers to allow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalExtensionRecommendedPermissionV1 {
    pub permission_id: String,
    pub label: Option<String>,
    pub description: Option<String>,
    pub example_command: Option<String>,
    pub extension_id: String,
    pub extension_name: Option<String>,
    pub rule_id: Option<String>,
    pub risk_tier: String,
    pub caution: bool,
    /// `critical`, `destructive` or `sensitive` when `caution` is set.
    pub caution_reason: Option<String>,
    pub caution_detail: Option<String>,
    pub cli_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalExtensionRecommendationV1 {
    /// `APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA`.
    pub schema: String,
    /// `available`, or `authority_unavailable` when the control authority is
    /// not healthy.
    pub status: String,
    pub permissions: Vec<ApprovalExtensionRecommendedPermissionV1>,
    pub caution: bool,
    pub revision: u64,
    pub catalog_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalExtensionRecommendationPayloadV1 {
    /// The recommendation, or null when the hint no longer applies.
    Recommend {
        recommendation: Option<ApprovalExtensionRecommendationV1>,
    },
    /// The asked risk classes that call for a caution, sorted without repeats.
    CautionRiskClasses { risk_classes: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalExtensionRecommendationResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_extension_recommendation_*`
    /// failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ApprovalExtensionRecommendationPayloadV1>,
}
