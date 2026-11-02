//! Explicit host-owned interpreter verification, independent of SDK setup.
use crate::{check_interpreter, InterpreterFacts, RuntimeError, RuntimeSelection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Non-deserializable observation, never an SDK activation or execution grant.
pub struct VerifiedInterpreter {
    path: PathBuf,
    sha256: String,
    facts: InterpreterFacts,
}
impl VerifiedInterpreter {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn facts(&self) -> &InterpreterFacts {
        &self.facts
    }
}

pub fn probe_interpreter_cancellable(
    python: &Path,
    private_work: &Path,
    cancel: Arc<AtomicBool>,
) -> Result<VerifiedInterpreter, RuntimeError> {
    probe(python, private_work, cancel, None, None)
}
/// Probe a fully pinned private distribution; repeat its tree check before
/// launch and after the fixed isolated probe. No SDK or feature is enabled.
pub fn probe_private_interpreter_cancellable(
    bundle: &guard_cigar_artifacts::VerifiedPythonBundle,
    private_work: &Path,
    cancel: Arc<AtomicBool>,
) -> Result<VerifiedInterpreter, RuntimeError> {
    let binding = bundle
        .build()
        .build()
        .binding()
        .map_err(|_| RuntimeError::ApprovalMismatch)?;
    probe(
        bundle.executable(),
        private_work,
        cancel,
        Some(crate::PrivatePythonSelection {
            root: bundle.root().into(),
            binding,
        }),
        Some(Arc::new(bundle.snapshot().clone())),
    )
}
fn probe(
    python: &Path,
    private_work: &Path,
    cancel: Arc<AtomicBool>,
    python_bundle: Option<crate::PrivatePythonSelection>,
    verified_python: Option<Arc<guard_cigar_artifacts::VerifiedPythonSnapshot>>,
) -> Result<VerifiedInterpreter, RuntimeError> {
    if cancel.load(Ordering::Acquire) {
        return Err(RuntimeError::Cancelled);
    }
    if !python.is_absolute()
        || !private_work.is_absolute()
        || python
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || fs::canonicalize(private_work).map_err(|_| RuntimeError::SelectionInvalid)?
            != private_work
    {
        return Err(RuntimeError::SelectionInvalid);
    }
    let directory =
        fs::symlink_metadata(private_work).map_err(|_| RuntimeError::SelectionInvalid)?;
    if !directory.is_dir() || directory.file_type().is_symlink() {
        return Err(RuntimeError::PackageUnsafe);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let executable = fs::metadata(python).map_err(|_| RuntimeError::ArtifactUnreadable)?;
        if executable.mode() & 0o022 != 0
            || directory.mode() & 0o077 != 0
            || directory.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(RuntimeError::PackageUnsafe);
        }
    }
    // Windows loads DLLs from the executable's folder first, so that folder
    // must be closed to other accounts as well.
    #[cfg(windows)]
    if !guard_cigar_artifacts::host::owned(python)
        || !python
            .parent()
            .is_some_and(guard_cigar_artifacts::host::owned)
        || !guard_cigar_artifacts::host::private_directory(private_work, &directory)
    {
        return Err(RuntimeError::PackageUnsafe);
    }
    let before = guard_secure_fs::read_stable(python, 128 * 1024 * 1024, true)
        .map_err(|_| RuntimeError::ArtifactUnreadable)?;
    let selection = RuntimeSelection {
        verified_python,
        python_bundle,
        python: python.to_path_buf(),
        site_packages: private_work.to_path_buf(),
        work_dir: private_work.to_path_buf(),
    };
    let facts: InterpreterFacts = serde_json::from_value(crate::process::probe(
        &selection,
        crate::runtime::PROBE,
        &cancel,
    )?)
    .map_err(|_| RuntimeError::Interpreter(crate::UnavailableReason::PythonReportInvalid))?;
    check_interpreter(&facts).map_err(RuntimeError::Interpreter)?;
    crate::private_python::check_selection(&selection, Some(&facts.platform), Some(&cancel))?;
    let after = guard_secure_fs::read_stable(python, 128 * 1024 * 1024, true)
        .map_err(|_| RuntimeError::ArtifactUnreadable)?;
    if before.identity != after.identity || before.sha256 != after.sha256 {
        return Err(RuntimeError::ApprovalMismatch);
    }
    Ok(VerifiedInterpreter {
        path: python.to_path_buf(),
        sha256: after.sha256,
        facts,
    })
}
