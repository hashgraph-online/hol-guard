//! Bind executable policy and retain non-executable inactive control intent.
use super::*;

impl CompiledNativeCommandControls {
    pub(crate) fn for_program(
        binding: &NativeCommandControlBindingV1,
        program: Arc<NativeCommandProgram>,
    ) -> Result<Self, &'static str> {
        Self::for_program_inner(binding, program, false)
    }

    /// Cache roots supply integrity proofs. The caller must independently
    /// authenticate the control binding before using this for policy execution.
    /// Filesystem reads belong only on snapshot admission, never a decision.
    pub fn from_pack_cache(
        binding: &NativeCommandControlBindingV1,
        directory: &std::path::Path,
        budget: crate::native_command_program::PackAdmissionBudget,
    ) -> Result<Self, &'static str> {
        binding.validate()?;
        let program =
            NativeCommandProgram::from_pack_cache(directory, &binding.program_digest, budget)?;
        Self::for_program_inner(binding, Arc::new(program), true)
    }
}

pub(super) fn validate_binding(
    binding: &NativeCommandControlBindingV1,
    program: &NativeCommandProgram,
) -> Result<(), &'static str> {
    binding.validate()?;
    if binding.program_digest != program.program_digest
        || binding.catalog_digest != program.catalog_digest
        || binding.trust_digest != program.trust_digest
    {
        return Err("native_command_program_binding_mismatch");
    }
    Ok(())
}

pub(super) fn may_retain_inactive(
    control: &guard_contracts::NativeExtensionControlV1,
    layer_kind: &str,
    known_extension: impl Fn(&str) -> bool,
) -> bool {
    if control.target_kind == "extension" {
        // Signed Cloud settings alone never opt external policy in. Local
        // enablement must have a completely admitted executable pack.
        return layer_kind != "local-admin" || control.state == "disabled";
    }
    // Preserve permission intent for an inactive owner. A missing permission
    // of a loaded owner remains an error, including missing Deny targets.
    control
        .target_id
        .split_once(".permission.")
        .is_some_and(|(owner, _)| !known_extension(owner))
}
