//! Observed package attribution for captured code, never a risk or grant.

use serde::{Deserialize, Serialize};

use crate::{NativeScriptCodeInputV1, NativeScriptInputKindV1};

/// Observational package attribution and assessment input, never permission.
pub const NATIVE_BASH_PACKAGE_EVIDENCE_FEATURE: &str = "native-bash-package-evidence-v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeScriptPackageStateV1 {
    Declared,
    MetadataUnavailable,
    MetadataInvalid,
    MetadataBudgetExceeded,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeScriptPackageBindingV1 {
    /// Opaque local root identity; no filesystem path is needed by Cloud.
    pub root_scope_sha256: String,
    pub ecosystem: String,
    /// These are declared identities, not verified registry provenance.
    pub name: Option<String>,
    pub version: Option<String>,
    /// Semantic attribution digest, not a digest of executable code.
    pub metadata_sha256: String,
    pub state: NativeScriptPackageStateV1,
    /// Indices into the subject's sorted, independently captured code inputs.
    pub code_input_indices: Vec<u16>,
}

pub(crate) fn validate_package_bindings(
    bindings: &[NativeScriptPackageBindingV1],
    code: &[NativeScriptCodeInputV1],
) -> Result<usize, &'static str> {
    use crate::native_bash_subject::digest;
    let invalid = "native_bash_subject_package_invalid";
    if bindings.len() > 64 {
        return Err(invalid);
    }
    let mut previous_root: Option<&str> = None;
    let mut claimed = std::collections::BTreeSet::new();
    let mut bytes = 0;
    for binding in bindings {
        if !digest(&binding.root_scope_sha256)
            || !digest(&binding.metadata_sha256)
            || binding.ecosystem != "npm"
            || previous_root.is_some_and(|root| root >= binding.root_scope_sha256.as_str())
            || binding.code_input_indices.is_empty()
            || binding.code_input_indices.len() > 64
            || binding
                .code_input_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid);
        }
        previous_root = Some(&binding.root_scope_sha256);
        let bounded = |value: &str, max: usize| {
            !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
        };
        match (&binding.name, &binding.version, binding.state) {
            (Some(name), Some(version), NativeScriptPackageStateV1::Declared)
                if bounded(name, 214) && bounded(version, 128) => {}
            (None, None, state) if state != NativeScriptPackageStateV1::Declared => {}
            _ => return Err(invalid),
        }
        for index in &binding.code_input_indices {
            let Some(input) = code.get(usize::from(*index)) else {
                return Err(invalid);
            };
            if input.kind == NativeScriptInputKindV1::Interpreter || !claimed.insert(*index) {
                return Err(invalid);
            }
        }
        bytes += 128
            + binding.name.as_ref().map_or(0, String::len)
            + binding.version.as_ref().map_or(0, String::len)
            + binding.code_input_indices.len() * 2;
    }
    Ok(bytes)
}
