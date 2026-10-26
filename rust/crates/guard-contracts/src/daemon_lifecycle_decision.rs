//! `DaemonLifecycleDecide` — wire contract for the resident op that owns the
//! pure decisions of the Guard daemon lifecycle manager: command-line
//! classification, process-inventory proof, port selection, health and state
//! classification, reservation claims and liveness gates.
//!
//! Python gathers the facts only the operating system can supply (a resolved
//! path, a pid probe, a decoded frozen payload, a Windows argv) and acts on
//! the verdict. Every fact the resident needs is requested lazily:
//! `{"need":"facts","keys":[...]}`; the caller repeats the identical request
//! with those keys added under `facts`. Missing facts are never assumed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DAEMON_LIFECYCLE_REQUEST_SCHEMA: &str = "guard-daemon-lifecycle-decision-request.v1";
pub const DAEMON_LIFECYCLE_RESULT_SCHEMA: &str = "guard-daemon-lifecycle-decision-result.v1";
pub const DAEMON_LIFECYCLE_FEATURE: &str = "daemon-lifecycle-decision-v1";
/// Largest request the op accepts (a process listing rides inside it).
pub const DAEMON_LIFECYCLE_MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonPlatformV1 {
    #[default]
    Posix,
    Nt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonInspectCommandQueryV1 {
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonInspectPartsQueryV1 {
    pub parts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonCommandIdentityQueryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_home: Option<String>,
    pub implicit_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonSameInvocationQueryV1 {
    pub left: String,
    pub right: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonProcessInventoryQueryV1 {
    pub guard_home: String,
    pub implicit_home: String,
    pub own_pid: i64,
    pub parent_pid: i64,
    pub frozen_runtime: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ps_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<(i64, String)>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonCompetingQueryV1 {
    pub inventory: Vec<(i64, i64)>,
    pub own_pid: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher_parent: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonEphemeralProcessesQueryV1 {
    pub ps_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonEphemeralHomeQueryV1 {
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfiguredPortQueryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_port: Option<String>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonCandidatePortsQueryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_port: Option<String>,
    pub guard_home: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_port: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonAdoptablePortsQueryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_port: Option<String>,
    pub guard_home: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub state_port: Value,
    pub running_ports: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonHealthzCurrentQueryV1 {
    pub raw_payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonHealthzHomeQueryV1 {
    pub raw_payload: String,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonStateShapeQueryV1 {
    pub payload: Value,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonIdentityBindingQueryV1 {
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonPayloadQueryV1 {
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonLocatorBindingQueryV1 {
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub state: Value,
    pub pid: i64,
    pub daemon_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonClaimQueryV1 {
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub existing: Value,
    pub now: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonOwnerStateQueryV1 {
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub reservation: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonStartProgressQueryV1 {
    pub record: Value,
    pub now_ns: i64,
    pub worker_ready_floor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonEphemeralInactiveQueryV1 {
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub state: Value,
    pub fallback_age_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonStartTimeoutsQueryV1 {
    pub desktop: bool,
    pub worker_ready_floor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum DaemonLifecycleQueryV1 {
    InspectCommand(DaemonInspectCommandQueryV1),
    SplitCommand(DaemonInspectCommandQueryV1),
    InspectParts(DaemonInspectPartsQueryV1),
    CommandIdentity(DaemonCommandIdentityQueryV1),
    SameInvocation(DaemonSameInvocationQueryV1),
    ProcessInventory(DaemonProcessInventoryQueryV1),
    CompetingDaemon(DaemonCompetingQueryV1),
    EphemeralProcesses(DaemonEphemeralProcessesQueryV1),
    EphemeralHome(DaemonEphemeralHomeQueryV1),
    ConfiguredPort(DaemonConfiguredPortQueryV1),
    CandidatePorts(DaemonCandidatePortsQueryV1),
    AdoptablePorts(DaemonAdoptablePortsQueryV1),
    HealthzCurrent(DaemonHealthzCurrentQueryV1),
    HealthzHome(DaemonHealthzHomeQueryV1),
    StateShape(DaemonStateShapeQueryV1),
    IdentityBinding(DaemonIdentityBindingQueryV1),
    LiveStateGate(DaemonPayloadQueryV1),
    LocatorShape(DaemonPayloadQueryV1),
    LocatorBinding(DaemonLocatorBindingQueryV1),
    WakeClaim(DaemonClaimQueryV1),
    RecoveryClaim(DaemonClaimQueryV1),
    RecoveryOwnerState(DaemonOwnerStateQueryV1),
    StartProgressLive(DaemonStartProgressQueryV1),
    EphemeralInactive(DaemonEphemeralInactiveQueryV1),
    StartTimeouts(DaemonStartTimeoutsQueryV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonLifecycleDecisionRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub platform: DaemonPlatformV1,
    #[serde(default)]
    pub facts: BTreeMap<String, Value>,
    pub query: DaemonLifecycleQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DaemonLifecycleDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Value,
}
