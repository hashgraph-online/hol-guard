//! Exact immutable installation reuse across qualification and historical slot
//! derivations. Listing and choosing candidates reads authenticated metadata.
use super::*;
use guard_cigar_release::{CatalogCheckpoint, ResolvedRelease};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshTarget {
    pub prior_record_sha256: String,
    pub catalog_checkpoint: CatalogCheckpoint,
    /// Informational: carried when the catalog entry names one. Refresh no
    /// longer requires it, since installation verifies each feature itself.
    #[serde(default)]
    pub qualification_receipt_sha256: Option<String>,
    pub guard_binary_sha256: String,
    pub features: Vec<Feature>,
}
impl RefreshTarget {
    pub fn validate(&self) -> Result<(), String> {
        if [
            Some(&self.prior_record_sha256),
            Some(&self.catalog_checkpoint.payload_sha256),
            self.qualification_receipt_sha256.as_ref(),
            Some(&self.guard_binary_sha256),
        ]
        .into_iter()
        .flatten()
        .any(|value| !is_lower_hex(value, 64))
            || self.catalog_checkpoint.revision == 0
            || self.features.len() > 4
            || !self.features.contains(&Feature::Graph)
            || self
                .features
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.features.len()
        {
            return Err(error("install_job_invalid"));
        }
        Ok(())
    }
}
pub(super) fn record_sha(record: &Installation) -> Result<String, String> {
    let bytes = serde_json::to_vec(record).map_err(|_| error("installation_invalid"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(super) fn physical_slot(
    release: &ResolvedRelease,
    approval: &BundleApproval,
) -> Result<String, String> {
    match &approval.python_bundle {
        Some(python) => guard_cigar_install::slot_id_with_python(release, python),
        None => guard_cigar_install::slot_id(release, &approval.python_sha256),
    }
    .map_err(|e| error(e.code()))
}
pub(super) fn find(
    home: &Path,
    release: &ResolvedRelease,
    interpreter: &interpreters::Interpreter,
    canonical_slot: &str,
) -> Result<Option<Installation>, String> {
    let settings = crate::guard_config_load::context_assistance_config(home)
        .map_err(|_| error("configuration_unavailable"))?;
    let mut matches = Vec::new();
    for value in super::super::list(home)? {
        let id = value["runtime_id"]
            .as_str()
            .ok_or_else(|| error("installation_invalid"))?;
        let record = load(home, id)?;
        if record.schema != versioned::SCHEMA_V2
            || record.selection.python != interpreter.python
            || record.interpreter != interpreter.facts
            || record.selection.python_bundle != interpreter.python_bundle()
        {
            continue;
        }
        let old = versioned::resolve(home, &record, &[Feature::Graph])?;
        if physical_slot(&old, &record.approval)? != canonical_slot {
            continue;
        }
        matches.push(record);
    }
    matches.sort_by(|a, b| {
        (a.runtime_id != settings.requested.runtime_id)
            .cmp(&(b.runtime_id != settings.requested.runtime_id))
            .then(
                (a.managed_slot.as_deref() != Some(canonical_slot))
                    .cmp(&(b.managed_slot.as_deref() != Some(canonical_slot))),
            )
            .then(a.runtime_id.cmp(&b.runtime_id))
    });
    let chosen = matches.into_iter().next();
    if let Some(record) = &chosen {
        let old = versioned::resolve(home, record, &[Feature::Graph])?;
        if old
            .platform()
            .features
            .iter()
            .any(|feature| !release.platform().features.contains(feature))
        {
            return Err(error("qualification_reduction_requires_switch"));
        }
    }
    Ok(chosen)
}
pub(super) fn target(
    record: &Installation,
    release: &ResolvedRelease,
) -> Result<RefreshTarget, String> {
    let target = RefreshTarget {
        prior_record_sha256: record_sha(record)?,
        catalog_checkpoint: release.checkpoint().clone(),
        qualification_receipt_sha256: release.platform().qualification_receipt_sha256.clone(),
        guard_binary_sha256: crate::resident_state::runtime_digest()?,
        features: release.platform().features.clone(),
    };
    target.validate()?;
    Ok(target)
}
pub(super) fn committed(
    home: &Path,
    job: &store::Job,
    record: &Installation,
) -> Result<bool, String> {
    let target = job
        .refresh
        .as_ref()
        .ok_or_else(|| error("install_job_invalid"))?;
    if record.verification_job_id.as_deref() != Some(job.request.job_id.as_str())
        || !worker::matches_installation(job, record, None)
    {
        return Ok(false);
    }
    let release = versioned::resolve(home, record, &target.features)?;
    if release.platform().qualification_receipt_sha256 != target.qualification_receipt_sha256
        || release.checkpoint() != &target.catalog_checkpoint
    {
        return Err(error("verification_conflict"));
    }
    let key = owner_key::read(home)?;
    let receipt = guard_cigar_release::verify_installation_receipt(
        record
            .receipt
            .as_ref()
            .ok_or_else(|| error("installation_invalid"))?,
        &key,
        &versioned::context(record, home)?,
    )
    .map_err(|e| error(e.code()))?;
    if receipt.metadata().guard_binary_sha256 != target.guard_binary_sha256 {
        return Err(error("verification_conflict"));
    }
    Ok(true)
}
