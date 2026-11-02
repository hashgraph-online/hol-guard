use crate::process::{self, JsonProcess};
use crate::release::RuntimeRelease;
use crate::{
    check_interpreter, BundleApproval, InterpreterFacts, RuntimeSelection, UnavailableReason,
};
#[cfg(test)]
use crate::{CIGAR_PROTOCOL, CIGAR_VERSION};
use guard_cigar_release::{ReleaseBinding, ResolvedRelease};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

#[path = "release_verification.rs"]
mod release_verification;

// Windows reports the host processor from `platform.machine()`, so an x64
// interpreter emulated on an ARM64 PC would claim arm64; the build tag names
// the interpreter itself.
pub(crate) const PROBE: &str = r#"
import json,platform,sys,sysconfig
machine={"aarch64":"arm64","amd64":"x64","x86_64":"x64"}.get(platform.machine().lower(),platform.machine().lower())
system={"Darwin":"darwin","Linux":"linux","Windows":"win32"}.get(platform.system(),"unknown")
if system=="win32":
    machine={"win-amd64":"x64","win-arm64":"arm64"}.get(sysconfig.get_platform(),machine)
target=system+"-"+machine
if system=="linux":
    abi=" ".join(str(sysconfig.get_config_var(key) or "") for key in ("MULTIARCH","HOST_GNU_TYPE","SOABI"))
    libc=platform.libc_ver()[0].lower()
    target+="-musl" if libc=="musl" or "musl" in abi else "-gnu" if libc=="glibc" else "-unknown"
print(json.dumps({"schema":"guard-cigar-interpreter.v1","implementation":sys.implementation.name,"version":list(sys.version_info[:3]),"release_level":sys.version_info.releaselevel,"free_threaded":bool(sysconfig.get_config_var("Py_GIL_DISABLED")),"debug_build":bool(sysconfig.get_config_var("Py_DEBUG")),"abi":sysconfig.get_config_var("SOABI") or "","platform":target}))
"#;

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
    Interpreter(UnavailableReason),
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
            Self::Interpreter(reason) => match reason {
                UnavailableReason::PythonReportInvalid => "python_report_invalid",
                UnavailableReason::PythonImplementationUnsupported => {
                    "python_implementation_unsupported"
                }
                UnavailableReason::PythonVersionUnsupported => "python_version_unsupported",
                UnavailableReason::PythonBuildUnqualified => "python_build_unqualified",
                UnavailableReason::PythonReleaseIncompatible => "python_release_incompatible",
                UnavailableReason::PlatformUnsupported => "platform_unsupported",
            },
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
    pub fn start(
        selection: RuntimeSelection,
        approval: &BundleApproval,
    ) -> Result<Self, RuntimeError> {
        Self::start_cancellable(selection, approval, Arc::new(AtomicBool::new(false)))
    }

    pub fn start_cancellable(
        selection: RuntimeSelection,
        approval: &BundleApproval,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, RuntimeError> {
        Self::start_bound(selection, approval, RuntimeRelease::legacy()?, cancel)
    }

    /// Normal activation requires trusted Guard qualification, then repeats
    /// actual protected-byte, interpreter and synthetic compilation checks.
    pub fn start_release_cancellable(
        selection: RuntimeSelection,
        approval: &BundleApproval,
        release: &ResolvedRelease,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, RuntimeError> {
        if !release.activation_qualified() {
            return Err(RuntimeError::ReleaseUnqualified);
        }
        Self::start_bound(
            selection,
            approval,
            RuntimeRelease::catalog(release)?,
            cancel,
        )
    }

    /// Explicit setup returns a stopped synthetic-doctor result. It never
    /// returns a usable runtime or authorizes workspace/source access.
    pub fn verify_release_candidate(
        selection: RuntimeSelection,
        approval: &BundleApproval,
        release: &ResolvedRelease,
    ) -> Result<RuntimeStatus, RuntimeError> {
        let mut runtime = Self::start_bound(
            selection,
            approval,
            RuntimeRelease::catalog(release)?,
            Arc::new(AtomicBool::new(false)),
        )?;
        runtime.close();
        Ok(runtime.status().clone())
    }

    fn start_bound(
        mut selection: RuntimeSelection,
        approval: &BundleApproval,
        expected: RuntimeRelease,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, RuntimeError> {
        if cancel.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        if !expected.matches(approval) {
            return Err(RuntimeError::ApprovalMismatch);
        }
        selection.verify_private_python(Some(&cancel))?;
        // Check expected bytes before executing even the interpreter probe.
        if crate::artifacts::inspect_cancellable(
            &selection,
            &approval.platform,
            &expected,
            &cancel,
        )? != *approval
        {
            return Err(RuntimeError::ApprovalMismatch);
        }
        let facts: InterpreterFacts =
            serde_json::from_value(process::probe(&selection, PROBE, &cancel)?)
                .map_err(|_| RuntimeError::Interpreter(UnavailableReason::PythonReportInvalid))?;
        check_interpreter(&facts).map_err(RuntimeError::Interpreter)?;
        expected.check_python_version(facts.version)?;
        if facts.platform != approval.platform {
            return Err(RuntimeError::ApprovalMismatch);
        }
        let mut process =
            JsonProcess::spawn_cancellable(&selection, expected.bridge()?, Arc::clone(&cancel))?;
        let doctor = process.rpc(json!({"op": "doctor"}), Duration::from_secs(5))?;
        let features = verify_doctor_for(&doctor, &expected)?;
        // Detect package or executable replacement during handshake/import.
        if crate::artifacts::inspect_cancellable(
            &selection,
            &approval.platform,
            &expected,
            &cancel,
        )? != *approval
        {
            return Err(RuntimeError::ApprovalMismatch);
        }
        let status = RuntimeStatus {
            schema: "guard-cigar-runtime-status.v1",
            interpreter: facts,
            package_version: expected.sdk_version.clone(),
            core_version: expected.core_version.clone(),
            protocol: expected.worker_protocol.clone(),
            adapter_id: expected.adapter_id.clone(),
            adapter_revision: expected.adapter_revision,
            release: expected.binding.clone(),
            package_fingerprint: approval.package_tree_sha256.clone(),
            worker_fingerprint: approval.worker_sha256.clone(),
            features,
            compile_verified: true,
            shared_compile_verified: false,
            persistence_compile_verified: false,
            execution_handoff_verified: false,
            active: true,
        };
        Ok(Self {
            process,
            selection,
            approval: approval.clone(),
            release: expected,
            status,
            graphs: crate::graph::GraphRegistry::default(),
            brokers: crate::broker::Registry::default(),
            cancel,
        })
    }

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
        match crate::artifacts::inspect_cancellable(
            &self.selection,
            &self.approval.platform,
            &self.release,
            &self.cancel,
        ) {
            Ok(observed) if observed == self.approval => Ok(()),
            Ok(_) => {
                self.close();
                Err(RuntimeError::ApprovalMismatch)
            }
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }

    pub fn close(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.brokers.close();
        self.process.stop();
        self.status.active = false;
    }

    pub(crate) fn spawn_private_client(
        &mut self,
        script: &str,
    ) -> Result<JsonProcess, RuntimeError> {
        self.recheck_artifacts()?;
        JsonProcess::spawn_cancellable(&self.selection, script, Arc::clone(&self.cancel))
    }
}

#[cfg(test)]
fn verify_doctor(doctor: &Value) -> Result<Vec<String>, RuntimeError> {
    verify_doctor_for(doctor, &RuntimeRelease::legacy()?)
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
