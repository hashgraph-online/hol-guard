//! CIGAR compiled into the Guard executable (`guard_cigar_native`).
//!
//! There is no interpreter, package or bridge script to verify: the engine is
//! part of the Guard binary that is already running, and the bridge and worker
//! are private modes of that same executable. Its identity is the engine
//! release compiled in, so the approval below is derived, never stored.
use super::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const BUILTIN_APPROVAL_SCHEMA: &str = "guard-cigar-builtin-approval.v1";
pub(crate) const BUILTIN_ADAPTER: &str = "guard-cigar-builtin-v1";
const BUILTIN_FACTS_SCHEMA: &str = "guard-cigar-builtin.v1";

/// The platform tag the downloaded bundles use for this build target.
pub fn builtin_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("windows", "x86_64") => "win32-x64",
        ("windows", "aarch64") => "win32-arm64",
        ("linux", "aarch64") if cfg!(target_env = "musl") => "linux-arm64-musl",
        ("linux", "x86_64") if cfg!(target_env = "musl") => "linux-x64-musl",
        ("linux", "aarch64") => "linux-arm64-gnu",
        ("linux", "x86_64") => "linux-x64-gnu",
        _ => "unknown",
    }
}

fn digest(label: &str) -> String {
    let identity = format!(
        "guard-cigar-builtin\0{label}\0{}\0{}\0{}\0{}",
        guard_cigar_native::CORE_VERSION,
        guard_cigar_native::WORKER_PROTOCOL,
        guard_cigar_native::BROKER_PROTOCOL,
        builtin_platform(),
    );
    format!("{:x}", Sha256::digest(identity.as_bytes()))
}

/// Same shape as a bundle approval so evidence and switch records keep one
/// format. Every digest names the compiled-in engine release, not files.
pub fn builtin_approval() -> BundleApproval {
    BundleApproval {
        schema: BUILTIN_APPROVAL_SCHEMA.into(),
        platform: builtin_platform().into(),
        python_sha256: digest("no-interpreter"),
        package_tree_sha256: digest("engine"),
        worker_sha256: digest("worker"),
        files: 0,
        bytes: 0,
        release: None,
    }
}

/// Status and registry records carry interpreter facts; the built-in engine
/// reports that there is none.
pub fn builtin_interpreter() -> InterpreterFacts {
    InterpreterFacts {
        schema: BUILTIN_FACTS_SCHEMA.into(),
        implementation: "guard-builtin".into(),
        version: [0, 0, 0],
        release_level: "final".into(),
        free_threaded: false,
        debug_build: false,
        abi: "none".into(),
        platform: builtin_platform().into(),
    }
}

/// `python` holds the Guard executable that hosts the bridge; there are no
/// site-packages.
pub fn builtin_selection(program: PathBuf, work_dir: PathBuf) -> RuntimeSelection {
    RuntimeSelection {
        python: program,
        site_packages: PathBuf::new(),
        work_dir,
    }
}

impl VerifiedRuntime {
    /// Start CIGAR from `program`, which must be this Guard executable: its
    /// `__guard-cigar-bridge` mode, then the same synthetic compile check the
    /// downloaded runtime passes.
    pub fn start_builtin(
        program: PathBuf,
        work_dir: PathBuf,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, RuntimeError> {
        if cancel.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        let expected = RuntimeRelease::builtin();
        let approval = builtin_approval();
        let selection = builtin_selection(program, work_dir);
        let mut process = JsonProcess::spawn_builtin(
            &selection.python,
            guard_cigar_native::BRIDGE_COMMAND,
            &selection.work_dir,
            Arc::clone(&cancel),
        )?;
        let doctor = startup_doctor(&mut process)?;
        let features = verify_doctor_for(&doctor, &expected)?;
        let status = RuntimeStatus {
            schema: "guard-cigar-runtime-status.v1",
            interpreter: builtin_interpreter(),
            package_version: expected.sdk_version.clone(),
            core_version: expected.core_version.clone(),
            protocol: expected.worker_protocol.clone(),
            adapter_id: expected.adapter_id.clone(),
            adapter_revision: expected.adapter_revision,
            release: None,
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
            approval,
            release: expected,
            status,
            graphs: crate::graph::GraphRegistry::default(),
            brokers: crate::broker::Registry::default(),
            cancel,
        })
    }

    /// True when this runtime is the engine compiled into Guard.
    pub fn is_builtin(&self) -> bool {
        self.release.is_builtin()
    }

    pub(super) fn spawn_builtin_client(&self) -> Result<JsonProcess, RuntimeError> {
        JsonProcess::spawn_builtin(
            &self.selection.python,
            guard_cigar_native::CLIENT_COMMAND,
            &self.selection.work_dir,
            Arc::clone(&self.cancel),
        )
    }
}
