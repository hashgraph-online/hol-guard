//! Redacted extension evidence shared by the command authority and edge.

use serde::{Deserialize, Serialize};

pub const NATIVE_COMMAND_OBSERVATIONS_SCHEMA: &str = "guard.native-command-observations.v1";
pub const NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA: &str = "guard.native-command-receipt-binding.v1";
pub const MAX_NATIVE_COMMAND_OBSERVATIONS: usize = 2_048;
pub const MAX_NATIVE_COMMAND_EVIDENCE_ITEMS: usize = 8_192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeMatcherEvidenceV1 {
    pub segment_index: usize,
    pub executable: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeSafeVariantObservationV1 {
    pub match_class: String,
    pub variant_id: String,
    pub matcher_evidence: Vec<NativeMatcherEvidenceV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandObservationV1 {
    pub extension_id: String,
    pub extension_version: String,
    pub rule_id: String,
    pub rule_version: String,
    pub match_class: String,
    pub match_classes: Vec<String>,
    pub matcher_evidence: Vec<NativeMatcherEvidenceV1>,
    pub safe_variants: Vec<NativeSafeVariantObservationV1>,
    pub uncertainty_reasons: Vec<String>,
    pub effective_segment_indexes: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandPermissionObservationV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    pub extension_id: String,
    pub permission_id: String,
    pub matcher_evidence: Vec<NativeMatcherEvidenceV1>,
    pub uncertainty_reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandObservationBatchV1 {
    pub observations: Vec<NativeCommandObservationV1>,
    pub permission_observations: Vec<NativeCommandPermissionObservationV1>,
    pub evaluation_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandReceiptBindingV1 {
    pub schema: String,
    pub program_digest: String,
    pub catalog_digest: String,
    pub trust_digest: String,
    pub control_revision: u64,
    pub managed_control_revision: u64,
    pub control_effective_digest: String,
    pub observations_digest: String,
    pub observation_count: usize,
    pub uncertainty_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandObservationsV1 {
    pub schema: String,
    pub binding: NativeCommandReceiptBindingV1,
    pub observations: Vec<NativeCommandObservationV1>,
    pub permission_observations: Vec<NativeCommandPermissionObservationV1>,
    pub evaluation_error: Option<String>,
}
