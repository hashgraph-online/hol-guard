//! The same measured feature checks serve activation and side-by-side updates.
use super::*;
use crate::policy_store::context_assistance_registry::Installation;
use guard_context_assistance::ContextAssistanceConfig;
use std::path::Path;

pub(super) fn runtime(
    installation: &Installation,
    home: &Path,
    config: &ContextAssistanceConfig,
    cancel: Arc<AtomicBool>,
) -> Result<VerifiedRuntime, String> {
    // The same refusal as starting the runtime: the SDK's store on Windows
    // holds every parent folder against renames while it is open.
    if config.storage.mode != StorageMode::Memory && !cfg!(unix) {
        return Err("native_context_assistance_persistence_unavailable".into());
    }
    #[cfg(test)]
    let started = Instant::now();
    #[cfg(test)]
    trace(config, "begin", started);
    let mut runtime = installation.start_cancellable(home, config, cancel)?;
    #[cfg(test)]
    trace(config, "runtime_started", started);
    if config.features.shared_agents {
        runtime
            .verify_shared_compile(config)
            .map_err(|e| format!("native_context_assistance_{}", e.code()))?;
    }
    #[cfg(test)]
    trace(config, "shared_verified", started);
    if config.storage.mode == StorageMode::Sqlite {
        runtime
            .verify_persistence_compile(home, config)
            .map_err(|e| format!("native_context_assistance_{}", e.code()))?;
    }
    #[cfg(test)]
    trace(config, "persistence_verified", started);
    if cfg!(target_os = "macos") && config.features.execution_context {
        // Preserve existing optional-lane behavior. A source lane that is
        // actually ready additionally requires target prewarming in the builder.
        let checked = runtime.verify_execution_handoff(config);
        if checked.is_err() && !runtime.status().active {
            return Err("native_context_assistance_execution_check_failed".into());
        }
    }
    if !runtime.status().active {
        return Err("native_context_assistance_runtime_closed".into());
    }
    #[cfg(test)]
    trace(config, "ready", started);
    Ok(runtime)
}
#[cfg(test)]
fn trace(config: &ContextAssistanceConfig, stage: &str, started: Instant) {
    eprintln!(
        "CIGAR_VERIFICATION_TIMING={}",
        json!({"runtime_id":config.runtime_id,"stage":stage,"elapsed_ms":started.elapsed().as_millis()})
    );
}
