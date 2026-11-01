//! Explicit maintainer/setup qualification; returns no usable runtime or grants.
use super::*;
use crate::{ContextAssistanceConfig, StorageMode};
use guard_cigar_release::Feature;
use std::path::Path;

impl VerifiedRuntime {
    /// Probe exact prepared bytes and requested synthetic feature paths without
    /// enabling CIGAR, granting user sources, selecting a runtime or turning an
    /// upstream-only release into an activation-qualified installation.
    pub fn verify_release_candidate_with_features(
        selection: RuntimeSelection,
        approval: &BundleApproval,
        release: &ResolvedRelease,
        qualification_home: &Path,
        features: &[Feature],
        cancel: Arc<AtomicBool>,
    ) -> Result<RuntimeStatus, RuntimeError> {
        if features.is_empty()
            || features.len() > 4
            || !features.contains(&Feature::Graph)
            || features
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != features.len()
        {
            return Err(RuntimeError::RequestInvalid);
        }
        let mut runtime = Self::start_bound(
            selection,
            approval,
            RuntimeRelease::catalog(release)?,
            cancel,
        )?;
        let mut config = ContextAssistanceConfig {
            runtime_id: "qualification:prepared".into(),
            ..Default::default()
        };
        config.features.agent_context = features.contains(&Feature::Sharing);
        config.features.shared_agents = features.contains(&Feature::Sharing);
        config.features.execution_context = features.contains(&Feature::ExecutionContext);
        if features.contains(&Feature::Persistence) {
            config.storage.mode = StorageMode::Sqlite;
        }
        let checked = (|| {
            if features.contains(&Feature::Sharing) {
                runtime.verify_shared_compile(&config)?;
            }
            if features.contains(&Feature::Persistence) {
                runtime.verify_persistence_compile(qualification_home, &config)?;
            }
            if features.contains(&Feature::ExecutionContext) {
                runtime.verify_execution_handoff(&config)?;
            }
            runtime.recheck_artifacts()
        })();
        runtime.close();
        checked?;
        Ok(runtime.status().clone())
    }
}
