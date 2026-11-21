//! Read-only observation of resident-owned execution, never permission.

use serde::{Deserialize, Serialize};

pub const NATIVE_BASH_ACTIVITY_FEATURE: &str = "native-bash-activity-v1";
pub const NATIVE_BASH_ACTIVITY_REQUEST_SCHEMA: &str = "guard-native-bash-activity-request.v1";
pub const NATIVE_BASH_ACTIVITY_RESULT_SCHEMA: &str = "guard-native-bash-activity-result.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashActivityRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub operation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashActivityV1 {
    pub operation_id: String,
    pub active: bool,
    pub cancellation_requested: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashActivityResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<NativeBashActivityV1>,
}
