use crate::process::{self, JsonProcess};
use crate::release::RuntimeRelease;
use crate::{BundleApproval, InterpreterFacts, RuntimeSelection};
use guard_cigar_release::ReleaseBinding;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

#[path = "runtime_builtin.rs"]
mod builtin;
pub(crate) use builtin::BUILTIN_ADAPTER;
pub use builtin::{
    builtin_approval, builtin_interpreter, builtin_platform, builtin_selection,
    BUILTIN_APPROVAL_SCHEMA,
};

/// The first reply includes the engine's synthetic compile check. A cold
/// start on a slow host (x64 under ARM64 emulation, or a fresh install that
/// antivirus is still scanning) takes several seconds. It never runs on the
/// synchronous hook path.
const STARTUP_RPC_TIMEOUT: Duration = process::PROBE_TIMEOUT;

fn startup_doctor(process: &mut JsonProcess) -> Result<Value, RuntimeError> {
    process.rpc(json!({"op": "doctor"}), STARTUP_RPC_TIMEOUT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeError {
    SelectionInvalid,
    ArtifactUnreadable,
    PackageUnsafe,
    BundleTooLarge,
    PackageMismatch,
    ApprovalMismatch,
    ReleaseUnqualified,
    PlatformUnqualified,
    LaunchFailed,
    DeadlineExceeded,
    TransportFailed,
    HandshakeFailed,
    RuntimeClosed,
    RequestInvalid,
    RequestTooLarge,
    Busy,
    WorkerRejected,
    ScopeDenied,
    ContextStale,
    ContextConflict,
    ResourceLimit,
    PathLimit,
    StorageRepairRequired,
    StorageOutcomeUnknown,
    DataPreparationUnsupported,
    Cancelled,
}

impl RuntimeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::SelectionInvalid => "runtime_selection_invalid",
            Self::ArtifactUnreadable => "runtime_artifact_unreadable",
            Self::PackageUnsafe => "runtime_package_unsafe",
            Self::BundleTooLarge => "runtime_bundle_too_large",
            Self::PackageMismatch => "runtime_package_mismatch",
            Self::ApprovalMismatch => "runtime_approval_mismatch",
            Self::ReleaseUnqualified => "runtime_release_unqualified",
            Self::PlatformUnqualified => "platform_unqualified",
            Self::LaunchFailed => "runtime_launch_failed",
            Self::DeadlineExceeded => "runtime_deadline_exceeded",
            Self::TransportFailed => "runtime_transport_failed",
            Self::HandshakeFailed => "runtime_handshake_failed",
            Self::RuntimeClosed => "runtime_closed",
            Self::RequestInvalid => "context_request_invalid",
            Self::RequestTooLarge => "context_request_too_large",
            Self::Busy => "context_busy",
            Self::WorkerRejected => "context_worker_rejected",
            Self::ScopeDenied => "context_scope_denied",
            Self::ContextStale => "context_stale",
            Self::ContextConflict => "context_conflict",
            Self::ResourceLimit => "context_resource_limit",
            Self::PathLimit => "context_path_limit",
            Self::StorageRepairRequired => "context_storage_repair_required",
            Self::StorageOutcomeUnknown => "context_storage_outcome_unknown",
            Self::DataPreparationUnsupported => "context_upgrade_data_unsupported",
            Self::Cancelled => "runtime_cancelled",
        }
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RuntimeError {}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeStatus {
    pub schema: &'static str,
    pub interpreter: InterpreterFacts,
    pub package_version: String,
    pub core_version: String,
    pub protocol: String,
    pub adapter_id: String,
    pub adapter_revision: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseBinding>,
    pub package_fingerprint: String,
    pub worker_fingerprint: String,
    pub features: Vec<String>,
    pub compile_verified: bool,
    pub shared_compile_verified: bool,
    pub persistence_compile_verified: bool,
    pub execution_handoff_verified: bool,
    pub active: bool,
}

/// Private, non-deserializable capability. Only actual isolated process and
/// artifact verification construct it. This is never an execution approval.
pub struct VerifiedRuntime {
    pub(crate) process: JsonProcess,
    selection: RuntimeSelection,
    approval: BundleApproval,
    release: RuntimeRelease,
    status: RuntimeStatus,
    pub(crate) graphs: crate::graph::GraphRegistry,
    pub(crate) brokers: crate::broker::Registry,
    pub(crate) cancel: Arc<AtomicBool>,
}

impl VerifiedRuntime {
    pub(crate) fn broker_protocol(&self) -> &str {
        &self.release.broker_protocol
    }

    /// Native installer metadata; these references never go to a consumer tool.
    pub fn installation_selection(&self) -> &RuntimeSelection {
        &self.selection
    }
    pub fn bundle_approval(&self) -> &BundleApproval {
        &self.approval
    }

    pub fn status(&self) -> &RuntimeStatus {
        &self.status
    }

    pub(crate) fn set_shared_verified(&mut self, verified: bool) {
        self.status.shared_compile_verified = verified;
    }
    pub(crate) fn set_persistence_verified(&mut self, verified: bool) {
        self.status.persistence_compile_verified = verified;
    }
    pub(crate) fn set_execution_verified(&mut self, verified: bool) {
        self.status.execution_handoff_verified = verified;
    }

    /// Active-service background heartbeat. It dispatches no SDK graph work;
    /// status reads and synchronous hooks never call it.
    pub fn check_transport(&mut self) -> Result<(), RuntimeError> {
        let result = self.rpc(json!({"op":"health"}), Duration::from_millis(100))?;
        if result != json!({"running":true}) {
            self.close();
            return Err(RuntimeError::TransportFailed);
        }
        Ok(())
    }

    pub(crate) fn rpc(&mut self, request: Value, timeout: Duration) -> Result<Value, RuntimeError> {
        let result = self.process.rpc(request, timeout);
        if matches!(
            result,
            Err(RuntimeError::DeadlineExceeded
                | RuntimeError::TransportFailed
                | RuntimeError::RuntimeClosed
                | RuntimeError::Cancelled)
        ) {
            self.close();
        }
        result
    }

    /// Revalidation belongs to explicit setup/recheck and graph activation,
    /// never the synchronous hook decision or approval path.
    pub fn recheck_artifacts(&mut self) -> Result<(), RuntimeError> {
        // The built-in engine is part of the running executable; there are
        // no separate bytes to change underneath it.
        if self.is_builtin() {
            return if self.status.active {
                Ok(())
            } else {
                Err(RuntimeError::RuntimeClosed)
            };
        }
        self.close();
        Err(RuntimeError::ApprovalMismatch)
    }

    pub fn close(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.brokers.close();
        self.process.stop();
        self.status.active = false;
    }

    pub(crate) fn spawn_private_client(&mut self) -> Result<JsonProcess, RuntimeError> {
        self.recheck_artifacts()?;
        self.spawn_builtin_client()
    }
}

#[cfg(test)]
fn verify_doctor(doctor: &Value) -> Result<Vec<String>, RuntimeError> {
    verify_doctor_for(doctor, &RuntimeRelease::builtin())
}

fn verify_doctor_for(
    doctor: &Value,
    expected: &RuntimeRelease,
) -> Result<Vec<String>, RuntimeError> {
    let capabilities = &doctor["capabilities"];
    let features = capabilities["features"]
        .as_array()
        .ok_or(RuntimeError::HandshakeFailed)?;
    let features: Vec<String> = features
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .filter(|item| item.len() <= 64)
                .ok_or(RuntimeError::HandshakeFailed)
        })
        .collect::<Result<_, _>>()?;
    let required = [
        "context_graph.v1",
        "context_views.v1",
        "snapshot_integrity.v1",
        "source_replace.v1",
        "selection_explanation.v1",
    ];
    if capabilities["schema"] != "cigar.local-worker-capabilities.v1"
        || capabilities["core_version"] != expected.core_version
        || capabilities["protocol"] != expected.worker_protocol
        || capabilities["execution"] != "isolated-process-serialized"
        || capabilities["authority"] != "trusted-host"
        || capabilities["requires_hol_services"] != false
        || capabilities["max_frame_bytes"] != 32 * 1024 * 1024
        || capabilities["max_response_bytes"] != 64 * 1024 * 1024
        || doctor["compile_verified"] != true
        || !doctor["rendered_tokens"]
            .as_u64()
            .is_some_and(|n| (1..=256).contains(&n))
        || features.len() > 64
        || required
            .iter()
            .any(|feature| !features.iter().any(|item| item == feature))
    {
        return Err(RuntimeError::HandshakeFailed);
    }
    Ok(features)
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
