//! `DaemonLifecycleDecide` resident op.
//!
//! Rust owns every pure decision of the Guard daemon lifecycle manager:
//! command-line classification, process-inventory proof, port selection,
//! health and state classification, reservation claims and liveness gates.
//! Python gathers the operating-system facts a decision names and acts on the
//! verdict. A malformed request is a bound error result; nothing falls back
//! to Python.

use guard_contracts::{
    DaemonLifecycleDecisionRequestV1, DaemonLifecycleDecisionResultV1, DaemonLifecycleQueryV1,
    DAEMON_LIFECYCLE_MAX_BYTES, DAEMON_LIFECYCLE_REQUEST_SCHEMA, DAEMON_LIFECYCLE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::context_digest_json::write_canonical_json_with_limit;
use crate::daemon_lifecycle_facts::Ctx;
use crate::daemon_lifecycle_state as state;
use crate::{daemon_lifecycle_claims as claims, daemon_lifecycle_command as command};
use crate::{daemon_lifecycle_inventory as inventory, daemon_lifecycle_ports as ports};

const INVALID: &str = "native_daemon_lifecycle_decision_invalid";
const SCHEMA_MISMATCH: &str = "native_daemon_lifecycle_decision_schema_mismatch";

fn request_digest(request: &DaemonLifecycleDecisionRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, DAEMON_LIFECYCLE_MAX_BYTES)
        .map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

/// The verdict for `request`, or the facts it still needs.
pub(crate) fn decide(request: &DaemonLifecycleDecisionRequestV1) -> Value {
    let ctx = Ctx::new(request.platform, &request.facts);
    let result = match &request.query {
        DaemonLifecycleQueryV1::InspectCommand(query) => command::inspect_command(&ctx, query),
        DaemonLifecycleQueryV1::SplitCommand(query) => command::split_command(&ctx, query),
        DaemonLifecycleQueryV1::CommandIdentity(query) => command::command_identity(&ctx, query),
        DaemonLifecycleQueryV1::InspectParts(query) => command::inspect_parts(&ctx, query),
        DaemonLifecycleQueryV1::SameInvocation(query) => command::same_invocation(&ctx, query),
        DaemonLifecycleQueryV1::ProcessInventory(query) => {
            inventory::process_inventory(&ctx, query)
        }
        DaemonLifecycleQueryV1::CompetingDaemon(query) => inventory::competing_daemon(query),
        DaemonLifecycleQueryV1::EphemeralProcesses(query) => {
            inventory::ephemeral_processes(&ctx, query)
        }
        DaemonLifecycleQueryV1::EphemeralHome(query) => inventory::ephemeral_home(&ctx, query),
        DaemonLifecycleQueryV1::ConfiguredPort(query) => ports::configured_port_result(&ctx, query),
        DaemonLifecycleQueryV1::CandidatePorts(query) => ports::candidate_ports(&ctx, query),
        DaemonLifecycleQueryV1::AdoptablePorts(query) => ports::adoptable_ports(&ctx, query),
        DaemonLifecycleQueryV1::HealthzCurrent(query) => state::healthz_current(query),
        DaemonLifecycleQueryV1::HealthzHome(query) => state::healthz_home(&ctx, query),
        DaemonLifecycleQueryV1::StateShape(query) => state::state_shape(&ctx, query),
        DaemonLifecycleQueryV1::IdentityBinding(query) => state::identity_binding(query),
        DaemonLifecycleQueryV1::LiveStateGate(query) => state::live_state_gate(&ctx, query),
        DaemonLifecycleQueryV1::LocatorShape(query) => state::locator_shape(&ctx, query),
        DaemonLifecycleQueryV1::LocatorBinding(query) => state::locator_binding(query),
        DaemonLifecycleQueryV1::WakeClaim(query) => claims::wake_claim(query),
        DaemonLifecycleQueryV1::RecoveryClaim(query) => claims::recovery_claim(&ctx, query),
        DaemonLifecycleQueryV1::RecoveryOwnerState(query) => {
            claims::recovery_owner_state(&ctx, query)
        }
        DaemonLifecycleQueryV1::StartProgressLive(query) => {
            claims::start_progress_live(&ctx, query)
        }
        DaemonLifecycleQueryV1::EphemeralInactive(query) => claims::ephemeral_inactive(&ctx, query),
        DaemonLifecycleQueryV1::StartTimeouts(query) => ports::start_timeouts(query),
    };
    ctx.finish(result)
}

pub(crate) fn evaluate_daemon_lifecycle_decision(
    request: &DaemonLifecycleDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, payload) = if request.schema != DAEMON_LIFECYCLE_REQUEST_SCHEMA {
        ("error", SCHEMA_MISMATCH, Value::Null)
    } else if request.request_id.len() > 128 {
        ("error", INVALID, Value::Null)
    } else {
        ("ok", "ok", decide(request))
    };
    crate::encode_response(&DaemonLifecycleDecisionResultV1 {
        schema: DAEMON_LIFECYCLE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}
