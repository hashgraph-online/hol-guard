//! Verify a fresh original SDK while the serving source is uninterrupted.
//! No app scope, source file, saved cache or old SDK grant enters this process.
use super::*;

pub(super) fn prepare(
    home: &Path,
    source: &Source,
    owner: &switching::Owner,
    id: &str,
    settings: &switching::SwitchSettings,
    signal: &Arc<Signal>,
) -> Result<VerifiedRuntime, String> {
    settings.check_current()?;
    let preparation = deadline::Deadline::preparing_recovery(Arc::clone(signal))?;
    let installation = registry::load(home, &source.settings.effective.runtime_id)?;
    let runtime = verification::runtime(
        &installation,
        home,
        settings.source(),
        Arc::clone(&signal.restore_cancel),
    )?;
    owner.verify_prepared_source(id, &installation, &runtime, settings.source())?;
    settings.check_current()?;
    preparation.finish();
    if signal.cancel.load(Ordering::Acquire) || signal.restore_cancel.load(Ordering::Acquire) {
        return Err(error("switch_cancelled"));
    }
    Ok(runtime)
}
