//! Refresh only an existing installation's measured qualification. Exact files,
//! registered paths, requested preferences and live CIGAR authority stay put.
use super::*;

pub(crate) fn publish_refresh_verified(
    home: &Path,
    old: &Installation,
    prior_record_sha256: &str,
    job_id: &str,
    release: &ResolvedRelease,
    runtime: &mut VerifiedRuntime,
) -> Result<Installation, String> {
    if !valid_id(job_id) || !release.activation_qualified() || old.schema != SCHEMA_V2 {
        return Err(error("installation_invalid"));
    }
    runtime.recheck_artifacts().map_err(|e| error(e.code()))?;
    let previous = resolve(home, old, &[Feature::Graph])?;
    if preparation::physical_slot(&previous, &old.approval)?
        != preparation::physical_slot(release, runtime.bundle_approval())?
        || runtime.bundle_approval() != &old.approval
        || runtime.installation_selection().python != old.selection.python
        || runtime.installation_selection().site_packages != old.selection.site_packages
        || runtime.installation_selection().python_bundle != old.selection.python_bundle
        || runtime.status().interpreter != old.interpreter
        || !runtime.status().active
        || !runtime.status().compile_verified
        || previous
            .platform()
            .features
            .iter()
            .any(|feature| !release.platform().features.contains(feature))
    {
        return Err(error("installation_conflict"));
    }
    let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let scratch = home
        .join("context-assistance/verification")
        .join(record_name(job_id).trim_end_matches(".json"));
    if runtime.installation_selection().work_dir != scratch {
        return Err(error("installation_invalid"));
    }
    let mut checked = vec![Feature::Graph];
    if runtime.status().shared_compile_verified {
        checked.push(Feature::Sharing);
    }
    if runtime.status().persistence_compile_verified {
        checked.push(Feature::Persistence);
    }
    if runtime.status().execution_handoff_verified {
        checked.push(Feature::ExecutionContext);
    }
    if release
        .platform()
        .features
        .iter()
        .any(|feature| !checked.contains(feature))
    {
        return Err(error("cigar_feature_unqualified"));
    }
    let directory = root(&home, true)?;
    let lock_path = directory.join("registry.lock");
    #[cfg(not(windows))]
    let lock = crate::resident_state::private_lock_file(&lock_path, &home)
        .map_err(|_| error("registry_unavailable"))?;
    #[cfg(windows)]
    let (lock, _binding) = crate::resident_state::private_lock_file(&lock_path, &home)
        .map_err(|_| error("registry_unavailable"))?;
    crate::resident_state::try_lock_exclusive_briefly(&lock).map_err(|_| error("registry_busy"))?;
    let current = load(&home, &old.runtime_id)?;
    if preparation::installation_record_sha(&current)? != prior_record_sha256 {
        return Err(error("verification_conflict"));
    }
    let mut record = current;
    record.verification_job_id = Some(job_id.into());
    let mut build = release.build().clone();
    build.platforms = vec![release.platform().clone()];
    let metadata = InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: build,
        profile: release.profile().clone(),
        platform: release.platform().platform.clone(),
        catalog_checkpoint: release.checkpoint().clone(),
        guard_binary_sha256: crate::resident_state::runtime_digest()?,
        context_sha256: context(&record, &home)?,
        verified_features: checked,
    };
    let key = owner_key::read(&home)?;
    record.receipt = Some(
        guard_cigar_release::seal_installation_receipt(&metadata, &key)
            .map_err(|e| error(e.code()))?,
    );
    resolve(&home, &record, &release.platform().features)?;
    // A final cancellation/policy check precedes the atomic metadata commit.
    runtime.recheck_artifacts().map_err(|e| error(e.code()))?;
    preparation::verification_policy(&home)?;
    let path = directory.join(record_name(&record.runtime_id));
    persist_private_bytes(
        &path,
        &serde_json::to_vec(&record).map_err(|_| error("installation_invalid"))?,
        MAX_RECORD,
        "cigar_installation",
        &home,
    )
    .map_err(|_| error("registry_write_failed"))?;
    load(&home, &record.runtime_id)
}
