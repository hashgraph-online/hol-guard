//! `ResidentHealth` — wire contract for the resident op that says whether the
//! resident is still serving, and how much room it has left.
//!
//! The existing `health` operation answers `ready` from the evaluation lane, so
//! a saturated resident refuses it with `native_overloaded` exactly as it
//! refuses work. A caller then cannot tell a busy resident from a dead one, and
//! both look like "native unavailable". This operation is routed onto the
//! reserved control lane instead, which keeps a worker and a quarter of the
//! queue out of evaluation capacity: an answer here means the process is alive
//! and authenticating, and the lane figures in it say how loaded it is.
//!
//! Every field is a count, a duration, or a build identifier the runtime
//! already publishes in its capabilities. Nothing here names a path, a command,
//! a request payload or a caller, because the health of the process must be
//! readable by a diagnostic that is not allowed to read the work it is doing.

use serde::{Deserialize, Serialize};

/// Resident feature advertising this op.
pub const RESIDENT_HEALTH_FEATURE: &str = "resident-health-v1";

/// Canonical request budget. The request carries a schema and an identifier, so
/// anything near this bound is malformed.
pub const RESIDENT_HEALTH_MAX_REQUEST_BYTES: usize = 4096;

/// Request schema identifier.
pub const RESIDENT_HEALTH_REQUEST_SCHEMA: &str = "guard-resident-health-request.v1";

/// Result schema identifier.
pub const RESIDENT_HEALTH_RESULT_SCHEMA: &str = "guard-resident-health-result.v1";

/// Request for the serving resident's own health.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidentHealthRequestV1 {
    /// Must equal [`RESIDENT_HEALTH_REQUEST_SCHEMA`].
    pub schema: String,
    /// Caller-chosen identifier the reply echoes.
    pub request_id: String,
}

/// One dispatch lane: the shape it was given at startup, and how full it is.
///
/// The first two numbers are decided when the resident starts, so a caller
/// that reads them knows what the depths beside them are measured against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidentLaneV1 {
    /// Worker threads reserved for this lane.
    pub workers: u32,
    /// Requests the lane's queue holds before it answers overload.
    pub queue_capacity: u32,
    /// Requests sitting in the lane's queue when this reply was built.
    pub queued: u32,
    /// The deepest this lane's queue has been since the resident started.
    /// A peak at `queue_capacity` says the lane has refused work, even when
    /// `queued` reads zero by the time anyone asks.
    pub queued_max: u32,
}

/// What the resident has done since it started serving.
///
/// Every field is a count or a duration in microseconds, summed or maximised
/// over served requests. None of them is keyed by a command, a path, a caller
/// or an operation, because this reply is read by a diagnostic that is not
/// allowed to read the work the resident is doing: a per-operation breakdown
/// would say which commands a machine runs, and a per-caller one would say who
/// ran them.
///
/// Totals saturate rather than wrap, so a long-lived resident reports a stuck
/// maximum rather than a figure that walks backwards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidentCountersV1 {
    /// Requests that were answered, whatever the answer said.
    pub served_requests: u64,
    /// Summed microseconds from admitting a request to writing its reply.
    /// Divided by `served_requests`, this is the mean service time; the
    /// resident does not keep the distribution that a percentile would need.
    pub service_micros_total: u64,
    /// The slowest single request, in microseconds.
    pub service_micros_max: u64,
    /// Summed request payload bytes, which is what the resident was asked to
    /// read, not what it decided about.
    pub request_bytes_total: u64,
    /// The largest single request payload, in bytes.
    pub request_bytes_max: u64,
    /// Connections that failed the shared-secret handshake or timed out in it.
    /// A rising count with no matching served requests is a client that cannot
    /// read the token, not a loaded resident.
    pub auth_failures: u64,
    /// Frames whose header, payload or reply could not be read or written.
    pub frame_errors: u64,
    /// Requests dropped because their total budget ran out before a worker
    /// reached them.
    pub deadline_exceeded: u64,
    /// Payloads whose contents did not match the digest in their header.
    pub digest_mismatches: u64,
    /// Evaluations that panicked and were answered `native_runtime_panicked`.
    pub panics: u64,
}

/// Reply carrying the resident's own view of itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidentHealthResultV1 {
    /// Must equal [`RESIDENT_HEALTH_RESULT_SCHEMA`].
    pub schema: String,
    /// Echo of the request's identifier.
    pub request_id: String,
    /// Digest of the request this reply answers.
    pub request_sha256: String,
    /// Always `serving`. A resident that cannot answer sends no reply at all,
    /// which is the distinction this operation exists to draw.
    pub status: String,
    /// Resident framing protocol version.
    pub protocol_version: u8,
    /// The runtime package version.
    pub runtime_version: String,
    /// The build this resident was compiled from, or `unknown`.
    pub build_sha: String,
    /// `arch-os` of the running binary.
    pub target: String,
    /// How long this resident has been accepting work.
    pub uptime_ms: u64,
    /// The evaluation lane, which carries hook and command work.
    pub evaluation: ResidentLaneV1,
    /// The control lane, which carries metadata work and this operation.
    pub control: ResidentLaneV1,
    /// Requests refused with `native_overloaded` since this resident started.
    /// A rising count beside a `serving` status is a loaded resident, not a
    /// broken one.
    pub overloaded_requests: u64,
    /// What this resident has served, and how it has failed, since it started.
    pub counters: ResidentCountersV1,
}
