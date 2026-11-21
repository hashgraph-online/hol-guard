//! Installation stamps are constructed only from an enrolled record and an
//! actually measured runtime. Operator labels cannot supply upstream identity.
use super::*;
use guard_cigar_release::{SelectionData, SelectionInstallation};
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
        let stored = context(&physical, home)?;
        let mut fresh_physical = fresh;
        fresh_physical.verification_job_id = None;
        if context(&fresh_physical, home)? != stored
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
        if self.schema != builtin::BUILTIN_SCHEMA {
            return Err(error("runtime_retired"));
        }
        let origin = builtin::origin();
        let producer =
            EvidenceUpgradeProducer::from_runtime(runtime).map_err(|e| error(e.code()))?;
        producer
            .revalidate_runtime(runtime)
            .map_err(|e| error(e.code()))?;
        let bytes =
            serde_json::to_vec(&self.approval).map_err(|_| error("switch_installation_invalid"))?;
        let pointer = SelectionPointer {
            runtime: SelectionInstallation {
                installation_id: self.runtime_id.clone(),
                installation_sha256: stored,
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
