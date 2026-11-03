//! Native owner review descriptors and read-only verification, never consent.

use crate::{NativeBashReviewLineageV1, NativeBashSubjectV1};
use serde::{Deserialize, Serialize};

pub const NATIVE_BASH_REVIEW_ARTIFACT_TYPE: &str = "native_bash_request";
pub const NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA: &str = "guard-native-bash-review.v4";
pub const NATIVE_BASH_REVIEW_DESCRIPTOR_FEATURE: &str = "native-bash-review-descriptor-v1";
pub const NATIVE_BASH_REVIEW_CHECK_REQUEST_SCHEMA: &str =
    "guard-native-bash-review-check-request.v1";
pub const NATIVE_BASH_REVIEW_CHECK_RESULT_SCHEMA: &str = "guard-native-bash-review-check-result.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeBashReviewDescriptorV1 {
    pub schema: String,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub subject: NativeBashSubjectV1,
    pub review_lineage: NativeBashReviewLineageV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashReviewCheckRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub store_path: String,
    pub approval_request_id: String,
    pub harness: String,
    pub command: String,
    pub descriptor: NativeBashReviewDescriptorV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashReviewCheckPayloadV1 {
    pub approval_request_id: String,
    pub lineage_id: String,
    pub artifact_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashReviewCheckResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<NativeBashReviewCheckPayloadV1>,
}
