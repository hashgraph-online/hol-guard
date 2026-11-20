//! The CIGAR engine compiled into this Guard executable, offered as the
//! reserved installation `builtin`. Nothing is downloaded or stored for it:
//! the record is derived from the running executable and the Guard home each
//! time, so it cannot go stale or be replaced on disk.
use super::*;
use guard_cigar_release::SelectionOrigin;
use std::sync::{atomic::AtomicBool, Arc};

/// Reserved runtime id. Enrollment and the downloaded-runtime installer
/// refuse it, so a stored record can never shadow the built-in engine.
pub(crate) const BUILTIN_ID: &str = "builtin";
pub(super) const BUILTIN_SCHEMA: &str = "guard-cigar-installation.builtin.v1";
const NO_SOURCE_REVISION: &str = "0000000000000000000000000000000000000000";

fn work_dir(home: &Path) -> Result<PathBuf, String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    Ok(home.join("context-assistance/work").join(BUILTIN_ID))
}

/// Creates the built-in working directory one private level at a time, so a
/// fresh home without `context-assistance/work` can still start the engine.
fn ensure_work_dir(canonical_home: &Path, work_dir: &Path) -> Result<(), String> {
    let relative = work_dir
        .strip_prefix(canonical_home)
        .map_err(|_| error("installation_invalid"))?;
    let mut current = canonical_home.to_path_buf();
    for component in relative.components() {
        current.push(component);
        crate::resident_state::ensure_private_directory_under(&current, canonical_home, true)
            .map_err(|_| error("registry_unavailable"))?;
    }
    Ok(())
}

pub(super) fn installation(home: &Path) -> Result<Installation, String> {
    root_path_ok(home)?;
    let program = std::env::current_exe().map_err(|_| error("installation_invalid"))?;
    if !program.is_absolute() {
        return Err(error("installation_invalid"));
    }
    Ok(Installation {
        schema: BUILTIN_SCHEMA.into(),
        runtime_id: BUILTIN_ID.into(),
        qualification: "guard_builtin".into(),
        source_revision: NO_SOURCE_REVISION.into(),
        selection: guard_context_assistance::builtin_selection(program, work_dir(home)?),
        approval: guard_context_assistance::builtin_approval(),
        interpreter: guard_context_assistance::builtin_interpreter(),
        receipt: None,
        managed_slot: None,
        verification_job_id: None,
    })
}

fn root_path_ok(home: &Path) -> Result<(), String> {
    if !home.is_absolute()
        || home
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(error("home_invalid"));
    }
    Ok(())
}

/// The list entry for the dashboard's runtime picker.
pub(super) fn choice() -> Value {
    json!({"runtime_id": BUILTIN_ID, "qualification": "guard_builtin",
        "python_version": null, "platform": guard_context_assistance::builtin_platform(),
        "worker_fingerprint": guard_context_assistance::builtin_approval().worker_sha256,
        "sdk_version": guard_cigar_native::CORE_VERSION,
        "core_version": guard_cigar_native::CORE_VERSION, "build_id": null,
        "adapter_id": "guard-cigar-builtin-v1", "adapter_revision": 1,
        "managed": false, "builtin": true})
}

pub(super) fn origin() -> SelectionOrigin {
    SelectionOrigin::Builtin {
        core_version: guard_cigar_native::CORE_VERSION.into(),
    }
}

pub(super) fn start(
    home: &Path,
    record: &Installation,
    cancel: Arc<AtomicBool>,
) -> Result<VerifiedRuntime, String> {
    let fresh = installation(home)?;
    if record.selection.python != fresh.selection.python
        || record.selection.work_dir != fresh.selection.work_dir
        || record.approval != fresh.approval
    {
        return Err(error("installation_invalid"));
    }
    let canonical = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    ensure_work_dir(&canonical, &fresh.selection.work_dir)?;
    VerifiedRuntime::start_builtin(
        fresh.selection.python.clone(),
        fresh.selection.work_dir.clone(),
        cancel,
    )
    .map_err(|e| error(e.code()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_dir_is_created_on_a_fresh_home() {
        let root = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(root.path()).unwrap();
        let work = work_dir(&home).unwrap();
        assert!(!home.join("context-assistance").exists());
        ensure_work_dir(&home, &work).unwrap();
        assert!(work.is_dir());
        ensure_work_dir(&home, &work).unwrap();
    }

    #[test]
    fn builtin_id_is_reserved_and_record_is_derived() {
        let home = std::env::temp_dir();
        let record = installation(&home).unwrap();
        assert_eq!(record.schema, BUILTIN_SCHEMA);
        assert_eq!(
            record.approval,
            guard_context_assistance::builtin_approval()
        );
        assert!(record
            .selection
            .work_dir
            .ends_with("context-assistance/work/builtin"));
        assert!(record.selection.python_bundle.is_none());
        assert!(installation(Path::new("relative")).is_err());
        assert_eq!(choice()["builtin"], true);
        assert!(matches!(origin(), SelectionOrigin::Builtin { .. }));
    }
}
