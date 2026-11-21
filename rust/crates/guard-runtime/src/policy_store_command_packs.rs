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
        let mut controls = if binding.program_digest == PACKAGED_COMMAND_PROGRAM_ID {
            CompiledNativeCommandControls::new(binding)?
        } else {
            // Independent control-path resource budgets; legacy representations
            // keep their existing limits. Exhaustion rejects the candidate snapshot.
            let budget = PackAdmissionBudget::resident();
            CompiledNativeCommandControls::from_pack_cache(
                binding,
                &state_base.join("command-packs"),
                budget,
            )?
        };
        let private_root = crate::resident_state::private_root_for_state_base(state_base)
            .map_err(|_| "native_active_pack_security_invalid")?;
        let record = super::policy_store_persistence::read_private_json(
            &state_base.join(crate::active_pack_security::FILE),
            262144,
            "active_security",
            &private_root,
        )
        .map_err(|_| "native_active_pack_security_invalid")?;
        let expected = if let Some((_, bytes)) = record {
            let key = super::read_verifier_key(state_base)
                .map_err(|_| "native_active_pack_security_invalid")?;
            let encoded =
                std::str::from_utf8(&bytes).map_err(|_| "native_active_pack_security_invalid")?;
            let security = crate::active_pack_security::Security::decode(encoded, &key)
                .map_err(|_| "native_active_pack_security_invalid")?;
            if security.program() != binding.program_digest {
                return Err("native_active_pack_security_program_mismatch");
            }
            controls.set_security_quarantine(security.pending(), &security.quarantine)?;
            security
                .applicable_digest()
                .map_err(|_| "native_active_pack_security_invalid")?
        } else {
            None
        };
        if expected != binding.active_security_digest {
            return Err("native_active_pack_security_binding_mismatch");
        }
        Ok(controls)
    })
}
