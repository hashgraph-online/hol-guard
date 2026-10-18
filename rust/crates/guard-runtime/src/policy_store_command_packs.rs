//! Pack cache reads occur only after snapshot authentication, before atomic
//! publication. Request evaluation retains the admitted immutable collection.
use super::*;
use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_command::native_command_program::{PackAdmissionBudget, PACKAGED_COMMAND_PROGRAM_ID};

#[cfg(test)]
impl PolicySnapshotStore {
    pub(crate) fn current_generation(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.snapshot.as_ref().map(|snapshot| snapshot.generation))
    }
}

pub(super) fn admit(
    snapshot: PolicySnapshotV3,
    state_base: &Path,
) -> Result<AdmittedPolicySnapshot, String> {
    AdmittedPolicySnapshot::with_command_loader(snapshot, |binding| {
        if binding.program_digest == PACKAGED_COMMAND_PROGRAM_ID {
            return CompiledNativeCommandControls::new(binding);
        }
        // Independent control-path resource budgets; legacy representations
        // keep their existing limits. Exhaustion rejects the candidate snapshot.
        let budget = PackAdmissionBudget::resident();
        CompiledNativeCommandControls::from_pack_cache(
            binding,
            &state_base.join("command-packs"),
            budget,
        )
    })
}
