//! Authenticated historical installation metadata. No passive operation probes
//! an interpreter, reads SDK files or changes selected/enabled preferences.
use super::*;
use guard_cigar_release::{Feature, InstalledReleaseReceipt, ResolvedRelease};
use guard_context_assistance::{ContextAssistanceConfig, StorageMode};
use std::sync::{atomic::AtomicBool, Arc};

#[path = "context_assistance_installation_refresh.rs"]
mod refresh;
pub(super) use refresh::publish_refresh_verified;

pub(super) const SCHEMA_V2: &str = "guard-cigar-installation.v2";

pub(super) fn context(record: &Installation, home: &Path) -> Result<String, String> {
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let mut value = json!({"schema":"guard-cigar-installation-context.v1","guard_home":home,
        "record_schema":record.schema,"runtime_id":record.runtime_id,"qualification":record.qualification,
        "source_revision":record.source_revision,"selection":record.selection,"approval":record.approval,
        "interpreter":record.interpreter,"managed_slot":record.managed_slot});
    if let Some(job_id) = &record.verification_job_id {
        value["verification_job_id"] = json!(job_id);
    }
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value)
        .map_err(|_| error("installation_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn managed_paths(home: &Path, record: &Installation) -> Result<(), String> {
    let slot = record
        .managed_slot
        .as_deref()
        .ok_or_else(|| error("installation_invalid"))?;
    if !is_lower_hex(slot, 64) {
        return Err(error("installation_invalid"));
    }
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    if record.selection.site_packages
        != home
            .join("context-assistance/bundles")
            .join(slot)
            .join("site-packages")
        || record.selection.work_dir != home.join("context-assistance/work").join(slot)
    {
        return Err(error("installation_invalid"));
    }
    Ok(())
}
pub(super) fn resolve(
    home: &Path,
    record: &Installation,
    features: &[Feature],
) -> Result<ResolvedRelease, String> {
    if record.schema != SCHEMA_V2
        || record.qualification != "guard_qualified"
        || record.approval.schema
            != if record.approval.python_bundle.is_some() {
                "guard-cigar-bundle-approval.v3"
            } else {
                "guard-cigar-bundle-approval.v2"
            }
        || record
            .verification_job_id
            .as_ref()
            .is_some_and(|id| !valid_id(id))
        || record.interpreter.platform != record.approval.platform
    {
        return Err(error("installation_invalid"));
    }
    managed_paths(home, record)?;
    preparation::validate_python_selection(
        home,
        &record.selection,
        &record.approval,
        &record.interpreter,
    )?;
    let key = owner_key::read(home)?;
    let receipt = record
        .receipt
        .as_ref()
        .ok_or_else(|| error("installation_invalid"))?;
    let verified =
        guard_cigar_release::verify_installation_receipt(receipt, &key, &context(record, home)?)
            .map_err(|e| error(e.code()))?;
    let current = super::catalog::installed(home)?;
    current.check_sdk(&verified.metadata().release.identity.build_id)?;
    let release = verified
        .resolve(&current.catalog, features)
        .map_err(|e| error(e.code()))?;
    if record.approval.release.as_ref() != Some(&release.binding().map_err(|e| error(e.code()))?)
        || record.approval.worker_sha256 != release.platform().worker_sha256
        || Some(&record.approval.package_tree_sha256)
            != release.platform().package_tree_sha256.as_ref()
        || record.source_revision != release.build().identity.source_revision
    {
        return Err(error("installation_invalid"));
    }
    Ok(release)
}
pub(super) fn features(config: &ContextAssistanceConfig) -> Vec<Feature> {
    let mut features = vec![Feature::Graph];
    if config.features.shared_agents {
        features.push(Feature::Sharing);
    }
    if config.storage.mode == StorageMode::Sqlite {
        features.push(Feature::Persistence);
    }
    if config.features.execution_context {
        features.push(Feature::ExecutionContext);
    }
    features
}
impl Installation {
    pub(crate) fn start_cancellable(
        &self,
        home: &Path,
        config: &ContextAssistanceConfig,
        cancel: Arc<AtomicBool>,
    ) -> Result<VerifiedRuntime, String> {
        match self.schema.as_str() {
            SCHEMA => {
                VerifiedRuntime::start_cancellable(self.selection.clone(), &self.approval, cancel)
                    .map_err(|e| error(e.code()))
            }
            SCHEMA_V2 => {
                let release = resolve(home, self, &features(config))?;
                VerifiedRuntime::start_release_cancellable(
                    self.selection.clone(),
                    &self.approval,
                    &release,
                    cancel,
                )
                .map_err(|e| error(e.code()))
            }
            _ => Err(error("installation_invalid")),
        }
    }
    pub(super) fn version_metadata(&self, home: &Path) -> Result<Value, String> {
        if self.schema == SCHEMA {
            let (legacy, profile) =
                guard_cigar_release::legacy_candidate_profile().map_err(|e| error(e.code()))?;
            Ok(
                json!({"sdk_version":legacy.sdk_version,"core_version":legacy.core_version,
                "build_id":null,"adapter_id":profile.adapter_id,"adapter_revision":profile.adapter_revision,
                "managed":false}),
            )
        } else {
            let release = resolve(home, self, &[Feature::Graph])?;
            Ok(
                json!({"sdk_version":release.build().identity.sdk_version,"core_version":release.build().identity.core_version,
                "build_id":release.build().identity.build_id,"adapter_id":release.profile().adapter_id,
                "adapter_revision":release.profile().adapter_revision,"managed":true}),
            )
        }
    }
}

/// Called by the native installer after its qualified runtime checks, never by
/// an HTTP payload or passive listing. It creates metadata without selection.
pub(crate) fn publish_verified(
    home: &Path,
    runtime_id: &str,
    slot: &str,
    release: &ResolvedRelease,
    runtime: &mut VerifiedRuntime,
) -> Result<Installation, String> {
    if !valid_id(runtime_id) || !release.activation_qualified() {
        return Err(error("installation_invalid"));
    }
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.write_cache = false;
    let settings = crate::guard_config_load::context_assistance_from_source(home, &source)
        .map_err(|_| error("configuration_unavailable"))?;
    if settings.diagnostic.is_some() || !settings.verification_permitted {
        return Err(error("policy_restricted"));
    }
    runtime.recheck_artifacts().map_err(|e| error(e.code()))?;
    let expected_slot = match &runtime.bundle_approval().python_bundle {
        Some(python) => guard_cigar_install::slot_id_with_python(release, python),
        None => guard_cigar_install::slot_id(release, &runtime.bundle_approval().python_sha256),
    }
    .map_err(|e| error(e.code()))?;
    if expected_slot != slot {
        return Err(error("installation_invalid"));
    }
    let status = runtime.status();
    if !status.active
        || !status.compile_verified
        || status.release.as_ref() != Some(&release.binding().map_err(|e| error(e.code()))?)
    {
        return Err(error("installation_invalid"));
    }
    let mut record = Installation {
        schema: SCHEMA_V2.into(),
        runtime_id: runtime_id.into(),
        qualification: "guard_qualified".into(),
        source_revision: release.build().identity.source_revision.clone(),
        selection: runtime.installation_selection().clone(),
        approval: runtime.bundle_approval().clone(),
        interpreter: status.interpreter.clone(),
        receipt: None,
        managed_slot: Some(slot.into()),
        verification_job_id: None,
    };
    managed_paths(home, &record)?;
    let directory = root(home, true)?;
    let lock_path = directory.join("registry.lock");
    #[cfg(not(windows))]
    let lock = crate::resident_state::private_lock_file(&lock_path, home)
        .map_err(|_| error("registry_unavailable"))?;
    #[cfg(windows)]
    let (lock, _binding) = crate::resident_state::private_lock_file(&lock_path, home)
        .map_err(|_| error("registry_unavailable"))?;
    crate::resident_state::try_lock_exclusive_briefly(&lock).map_err(|_| error("registry_busy"))?;
    let path = directory.join(record_name(runtime_id));
    if fs::symlink_metadata(&path).is_ok() {
        return Err(error("installation_exists"));
    }
    let count = fs::read_dir(&directory)
        .map_err(|_| error("registry_unavailable"))?
        .try_fold(0usize, |count, entry| {
            let entry = entry.map_err(|_| error("registry_unavailable"))?;
            Ok::<usize, String>(
                count + usize::from(entry.path().extension().is_some_and(|ext| ext == "json")),
            )
        })?;
    if count >= 8 {
        return Err(error("installation_limit"));
    }
    let mut build = release.build().clone();
    build.platforms = vec![release.platform().clone()];
    let mut checked = vec![Feature::Graph];
    if status.shared_compile_verified {
        checked.push(Feature::Sharing);
    }
    if status.persistence_compile_verified {
        checked.push(Feature::Persistence);
    }
    if status.execution_handoff_verified {
        checked.push(Feature::ExecutionContext);
    }
    let metadata = InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: build,
        profile: release.profile().clone(),
        platform: release.platform().platform.clone(),
        catalog_checkpoint: release.checkpoint().clone(),
        guard_binary_sha256: crate::resident_state::runtime_digest()?,
        context_sha256: context(&record, home)?,
        verified_features: checked,
    };
    let key = owner_key::provision_locked(home)?;
    record.receipt = Some(
        guard_cigar_release::seal_installation_receipt(&metadata, &key)
            .map_err(|e| error(e.code()))?,
    );
    resolve(home, &record, &[Feature::Graph])?;
    let bytes = serde_json::to_vec(&record).map_err(|_| error("installation_invalid"))?;
    persist_private_bytes(&path, &bytes, MAX_RECORD, "cigar_installation", home)
        .map_err(|_| error("registry_write_failed"))?;
    load(home, runtime_id)
}
