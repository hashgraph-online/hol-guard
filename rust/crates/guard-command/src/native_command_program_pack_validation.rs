//! Offline compiler pack validation; not a runtime admission API.
use super::*;

impl NativeCommandProgram {
    // Offline compiler validation only: a pack may own a strict subset of the
    // compatibility inventory. The complete release must still own every ID.
    // This is not exposed as a runtime program or filesystem admission API.
    #[cfg(test)]
    pub(in crate::native_command_program) fn validate_compiler_pack(
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        Self::validate_compiler_pack_with_interfaces(bytes, (&BTreeSet::new(), &BTreeSet::new()))
    }

    pub(in crate::native_command_program) fn validate_compiler_pack_with_interfaces(
        bytes: &[u8],
        interfaces: (&BTreeSet<String>, &BTreeSet<String>),
    ) -> Result<(), &'static str> {
        Self::from_bytes_observed(bytes, &mut |_| {}, Some(interfaces)).map(|_| ())
    }
}
