//! SDK observation of a durable native result. This cannot grant execution.
use serde::{Deserialize, Serialize};

pub const NATIVE_BASH_INVOCATION_FEATURE: &str = "native-bash-invocation-lifetime-v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashAckRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub store_path: String,
    pub base_id: String,
    pub harness: String,
    pub project: String,
    pub tool_call_id: String,
    pub exit_code: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashAckResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub acknowledged: bool,
}
