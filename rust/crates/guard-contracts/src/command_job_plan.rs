//! `CommandJobPlan` — wire contract for the resident op that plans a leased
//! Guard Cloud command job.
//!
//! The request names the job's operation and the payload fields that decide
//! how it runs. The result says whether the job fails before it runs, waits
//! for a local confirmation command (with that command already built), or
//! runs one of the local operation families with validated arguments. The op
//! is pure: it reads no file and runs nothing.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const COMMAND_JOB_PLAN_REQUEST_SCHEMA: &str = "guard-command-job-plan-request.v1";
/// Schema discriminator for the result.
pub const COMMAND_JOB_PLAN_RESULT_SCHEMA: &str = "guard-command-job-plan-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMMAND_JOB_PLAN_FEATURE: &str = "command-job-plan-v1";
/// Largest canonical request serialization the op will accept.
pub const COMMAND_JOB_PLAN_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandJobPlanRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: CommandJobPlanQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandJobPlanQueryV1 {
    /// Plan one job. Each field carries the job's raw value, or null when the
    /// job has none, so the op applies the same type checks the queue did.
    Plan {
        operation: Option<Value>,
        harness: Option<Value>,
        surface: Option<Value>,
        managers: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandJobPlanPayloadV1 {
    Plan { plan: CommandJobPlanV1 },
}

/// What the queue does with the job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandJobPlanV1 {
    /// Post `failed` without running anything.
    Fail {
        failure_code: String,
        failure_message: String,
    },
    /// Post `waiting_local_confirm` with `data`; nothing runs until the user
    /// runs the confirmation command on this machine.
    Confirm { data: Map<String, Value> },
    /// Run `operation` in `family` with the validated arguments.
    Run {
        operation: String,
        /// `package_shims`, `app`, `exact_cloud_review` or `policy_memory`.
        family: String,
        /// The normalized manager names, or null for every manager.
        managers: Option<Vec<String>>,
        harness: Option<String>,
        surface: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandJobPlanResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_job_plan_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<CommandJobPlanPayloadV1>,
}
