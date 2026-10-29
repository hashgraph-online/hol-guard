//! Installation stamps are constructed only from an enrolled record and an
//! actually measured runtime. Operator labels cannot supply upstream identity.
use super::*;
use guard_cigar_release::{SelectionData, SelectionInstallation, SelectionOrigin};
use guard_context_assistance::EvidenceUpgradeProducer;

impl Installation {
    pub(crate) fn measured_selection(
        &self,
        home: &Path,
        runtime: &VerifiedRuntime,
        data: SelectionData,
    ) -> Result<(SelectionPointer, EvidenceUpgradeProducer), String> {
        let fresh = load(home, &self.runtime_id)?;
        let mut physical = self.clone();
        physical.verification_job_id = None;
        let context = versioned::context(&physical, home)?;
        let mut fresh_physical = fresh;
        fresh_physical.verification_job_id = None;
        if versioned::context(&fresh_physical, home)? != context
            || runtime.bundle_approval() != &self.approval
            || serde_json::to_value(runtime.installation_selection())
                .map_err(|_| error("switch_installation_invalid"))?
                != serde_json::to_value(&self.selection)
                    .map_err(|_| error("switch_installation_invalid"))?
            || !runtime.status().active
            || !runtime.status().compile_verified
        {
            return Err(error("switch_installation_changed"));
        }
        let (origin, producer) = if self.schema == SCHEMA {
            let (legacy, profile) =
                guard_cigar_release::legacy_candidate_profile().map_err(|e| error(e.code()))?;
            (
                SelectionOrigin::Enrolled {
                    sdk_version: legacy.sdk_version,
                    core_version: legacy.core_version,
                    profile_id: profile.profile_id,
                    adapter_id: profile.adapter_id,
                    adapter_revision: profile.adapter_revision,
                },
                EvidenceUpgradeProducer::from_enrolled_runtime(runtime)
                    .map_err(|e| error(e.code()))?,
            )
        } else {
            let release = versioned::resolve(home, self, &[Feature::Graph])?;
            (
                SelectionOrigin::Catalog {
                    release: Box::new(release.binding().map_err(|e| error(e.code()))?),
                },
                EvidenceUpgradeProducer::new(&release, runtime.bundle_approval())
                    .map_err(|e| error(e.code()))?,
            )
        };
        producer
            .revalidate_runtime(runtime)
            .map_err(|e| error(e.code()))?;
        let bytes =
            serde_json::to_vec(&self.approval).map_err(|_| error("switch_installation_invalid"))?;
        let pointer = SelectionPointer {
            runtime: SelectionInstallation {
                installation_id: self.runtime_id.clone(),
                installation_sha256: context,
                approval_sha256: format!("{:x}", Sha256::digest(bytes)),
                producer_sha256: producer.identity_sha256().into(),
                origin,
            },
            data,
        };
        pointer.validate().map_err(state_error)?;
        Ok((pointer, producer))
    }
}
