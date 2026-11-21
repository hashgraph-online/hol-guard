//! Captured code identity and shared graph input limits.

use super::{Builder, Code, CodeIdentity, Result, Uncertainty, MAX_CODE_INPUTS, MAX_SOURCE_BYTES};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub(super) enum Kind {
    Code,
    Source,
    Startup,
}

impl Builder<'_> {
    pub(super) fn register(&mut self, code: &Code, kind: Kind) -> Result<()> {
        let error = |reason| Uncertainty { reason, line: 1 };
        if code.original_path.is_empty()
            || code.original_path.contains('\0')
            || code.resolved_path.contains('\0')
            || code.original_path.len() > 4096
            || code.resolved_path.len() > 4096
            || !code.resolved_path.starts_with('/')
        {
            return Err(error("bash_input_path_bounds"));
        }
        if Instant::now() >= self.deadline {
            return Err(error("bash_analysis_timeout"));
        }
        if self.active.contains(&code.resolved_path) {
            return Err(error("bash_helper_cycle"));
        }
        let digest = hex::encode(Sha256::digest(code.source.as_bytes()));
        if let Some(previous) = self.snapshots.get(&code.resolved_path) {
            if previous != &digest {
                return Err(error("bash_code_changed_during_analysis"));
            }
        } else {
            self.bytes += code.source.len();
            if self.bytes > MAX_SOURCE_BYTES || self.snapshots.len() >= MAX_CODE_INPUTS {
                return Err(error("bash_graph_bounds"));
            }
            self.snapshots
                .insert(code.resolved_path.clone(), digest.clone());
        }
        let total = self.code.len()
            + self.sources.len()
            + self.startup.len()
            + self.native_images.len()
            + self.brokered_images.len()
            + 1;
        let inputs = match kind {
            Kind::Code => &mut self.code,
            Kind::Source => &mut self.sources,
            Kind::Startup => &mut self.startup,
        };
        if !inputs.contains_key(&code.original_path) && total >= MAX_CODE_INPUTS {
            return Err(error("bash_graph_bounds"));
        }
        // Original spellings are also identity: two symlinks can give a helper
        // different $0 semantics even when they name identical code bytes.
        if inputs.get(&code.original_path).is_some_and(|previous| {
            previous.resolved_path != code.resolved_path || previous.content_sha256 != digest
        }) {
            return Err(error("bash_resolution_changed_during_analysis"));
        }
        inputs.insert(
            code.original_path.clone(),
            CodeIdentity {
                original_path: code.original_path.clone(),
                resolved_path: code.resolved_path.clone(),
                content_sha256: digest,
            },
        );
        Ok(())
    }
}
