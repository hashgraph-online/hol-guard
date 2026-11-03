//! Owner-authenticated private Python installations. Passive resolution reads
//! metadata only; publication/use must repeat complete tree and process checks.
use super::*;
use guard_cigar_install::{verify_python_tree, PreparationControl, VerifiedPythonBundle};
use guard_cigar_release::{
    InstalledInterpreterReceipt, ResolvedInterpreterBuild, SealedInterpreterReceipt,
};
use guard_context_assistance::{PrivatePythonSelection, VerifiedInterpreter};

pub(super) const SCHEMA: &str = "guard-cigar-interpreter-installation.v2";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedPython {
    pub selection: PrivatePythonSelection,
    pub receipt: SealedInterpreterReceipt,
}
pub(super) fn identity(
    python: &Path,
    sha256: &str,
    facts: &InterpreterFacts,
    selection: &PrivatePythonSelection,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        "guard-cigar-interpreter-id.v2",
        python,
        sha256,
        facts,
        selection,
    ))
    .map_err(|_| error("interpreter_invalid"))?;
    Ok(format!("python:{:x}", Sha256::digest(bytes)))
}
fn context(
    home: &Path,
    record: &interpreters::Interpreter,
    selection: &PrivatePythonSelection,
) -> Result<String, String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let value = json!({"schema":"guard-cigar-interpreter-context.v1", "guard_home":home,
        "record_schema":record.schema,"interpreter_id":record.interpreter_id,
        "python":record.python,"python_sha256":record.python_sha256,
        "facts":record.facts,"selection":selection});
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value)
        .map_err(|_| error("interpreter_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn paths(home: &Path, python: &Path, selection: &PrivatePythonSelection) -> Result<(), String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let slot = selection.binding.slot_id().map_err(|e| error(e.code()))?;
    if selection.root
        != home
            .join("context-assistance/python")
            .join(slot)
            .join("python")
        || python != selection.root.join(selection.binding.executable())
    {
        return Err(error("interpreter_invalid"));
    }
    Ok(())
}
pub(super) fn resolve(
    home: &Path,
    record: &interpreters::Interpreter,
) -> Result<ResolvedInterpreterBuild, String> {
    let managed = record
        .managed_python
        .as_ref()
        .ok_or_else(|| error("interpreter_invalid"))?;
    paths(home, &record.python, &managed.selection)?;
    if record.schema != SCHEMA
        || record.interpreter_id
            != identity(
                &record.python,
                &record.python_sha256,
                &record.facts,
                &managed.selection,
            )?
        || record.python_sha256 != managed.selection.binding.executable_sha256
        || record.facts.version != managed.selection.binding.python_version
        || record.facts.platform != managed.selection.binding.platform
    {
        return Err(error("interpreter_invalid"));
    }
    let key = owner_key::read(home)?;
    let verified = guard_cigar_release::verify_interpreter_receipt(
        &managed.receipt,
        &key,
        &context(home, record, &managed.selection)?,
    )
    .map_err(|e| error(e.code()))?;
    let current = super::super::catalog::installed(home)?;
    current.check_python(&verified.metadata().build.build_id)?;
    let build = verified
        .resolve(&current.catalog)
        .map_err(|e| error(e.code()))?;
    if build.build().binding().map_err(|e| error(e.code()))? != managed.selection.binding {
        return Err(error("interpreter_invalid"));
    }
    Ok(build)
}
pub(super) fn validate_selection(
    home: &Path,
    selection: &RuntimeSelection,
    approval: &BundleApproval,
    facts: &InterpreterFacts,
) -> Result<(), String> {
    match (&selection.python_bundle, &approval.python_bundle) {
        (None, None) => Ok(()),
        (Some(python), Some(binding)) if &python.binding == binding => {
            let id = identity(&selection.python, &approval.python_sha256, facts, python)?;
            let record = interpreters::load_interpreter(home, &id)?;
            if record.managed_python.as_ref().map(|value| &value.selection) != Some(python)
                || record.python != selection.python
                || record.facts != *facts
            {
                return Err(error("interpreter_invalid"));
            }
            resolve(home, &record).map(|_| ())
        }
        _ => Err(error("interpreter_invalid")),
    }
}
pub(super) fn verify_for_use(
    home: &Path,
    record: &interpreters::Interpreter,
    control: &PreparationControl,
) -> Result<Option<Arc<guard_cigar_install::VerifiedPythonSnapshot>>, String> {
    let snapshot = if let Some(managed) = &record.managed_python {
        let build = resolve(home, record)?;
        let bundle = verify_python_tree(&build, &managed.selection.root, control)
            .map_err(|e| error(e.code()))?;
        Some(Arc::new(bundle.snapshot().clone()))
    } else {
        None
    };
    control.checkpoint().map_err(|e| error(e.code()))?;
    Ok(snapshot)
}
pub(super) fn refuse_external_alias(home: &Path, python: &Path) -> Result<(), String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let actual = fs::canonicalize(python).map_err(|_| error("interpreter_unreadable"))?;
    for namespace in ["python", "python-staging"] {
        let managed = home.join("context-assistance").join(namespace);
        if python.starts_with(&managed) || actual.starts_with(&managed) {
            return Err(error("interpreter_managed_setup_required"));
        }
    }
    Ok(())
}

/// Caller owns the preparation lease. The opaque inputs must agree on exact
/// bytes and actual interpreter facts; no serialized request can publish them.
pub(super) fn publish(
    home: &Path,
    bundle: &VerifiedPythonBundle,
    observed: &VerifiedInterpreter,
    control: &PreparationControl,
) -> Result<interpreters::Interpreter, String> {
    worker::policy(home)?;
    let build = bundle.build();
    if !build.setup_qualified() {
        return Err(error("interpreter_invalid"));
    }
    let selection = PrivatePythonSelection {
        root: bundle.root().into(),
        binding: build.build().binding().map_err(|e| error(e.code()))?,
    };
    paths(home, bundle.executable(), &selection)?;
    if observed.path() != bundle.executable()
        || observed.sha256() != selection.binding.executable_sha256
        || observed.facts().version != selection.binding.python_version
        || observed.facts().platform != selection.binding.platform
        || guard_context_assistance::check_interpreter(observed.facts()).is_err()
    {
        return Err(error("interpreter_changed"));
    }
    bundle
        .snapshot()
        .recheck_controlled(control)
        .map_err(|e| error(e.code()))?;
    let mut record = interpreters::Interpreter {
        schema: SCHEMA.into(),
        interpreter_id: identity(
            observed.path(),
            observed.sha256(),
            observed.facts(),
            &selection,
        )?,
        python: observed.path().into(),
        python_sha256: observed.sha256().into(),
        facts: observed.facts().clone(),
        managed_python: None,
    };
    let directory = store::directory(home, "interpreters", true)?;
    let registry = root(home, true)?;
    let lock_path = registry.join("registry.lock");
    #[cfg(not(windows))]
    let lock = crate::resident_state::private_lock_file(&lock_path, home)
        .map_err(|_| error("registry_unavailable"))?;
    #[cfg(windows)]
    let (lock, _binding) = crate::resident_state::private_lock_file(&lock_path, home)
        .map_err(|_| error("registry_unavailable"))?;
    crate::resident_state::try_lock_exclusive_briefly(&lock).map_err(|_| error("registry_busy"))?;
    let path = directory.join(record_name(&record.interpreter_id));
    if let Ok(existing) = interpreters::load_interpreter(home, &record.interpreter_id) {
        return Ok(existing);
    }
    if fs::symlink_metadata(&path).is_ok() {
        return Err(error("interpreter_invalid"));
    }
    if interpreters::interpreters(home)?.len() >= 16 {
        return Err(error("interpreter_limit"));
    }
    let metadata = InstalledInterpreterReceipt {
        schema: "guard-cigar-installed-python.v1".into(),
        build: build.build().clone(),
        catalog_checkpoint: build.checkpoint().clone(),
        guard_binary_sha256: crate::resident_state::runtime_digest()?,
        context_sha256: context(home, &record, &selection)?,
    };
    let key = owner_key::provision_locked(home)?;
    record.managed_python = Some(ManagedPython {
        selection,
        receipt: guard_cigar_release::seal_interpreter_receipt(&metadata, &key)
            .map_err(|e| error(e.code()))?,
    });
    resolve(home, &record)?;
    control.checkpoint().map_err(|e| error(e.code()))?;
    persist_private_bytes(
        &path,
        &serde_json::to_vec(&record).map_err(|_| error("interpreter_invalid"))?,
        16 * 1024,
        "cigar_interpreter",
        home,
    )
    .map_err(|_| error("interpreter_write_failed"))?;
    interpreters::load_interpreter(home, &record.interpreter_id)
}
