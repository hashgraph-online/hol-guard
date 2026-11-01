//! Disposable verified SDKs have independent forwarded cancellation.
use super::*;
pub(super) struct PrivateRuntime {
    pub(super) runtime: VerifiedRuntime,
    _cancel: deadline::Deadline,
}
impl PrivateRuntime {
    pub(super) fn start(
        installation: &registry::Installation,
        home: &Path,
        config: &guard_context_assistance::ContextAssistanceConfig,
        signal: &Arc<Signal>,
    ) -> Result<Self, String> {
        let cancel = Arc::new(AtomicBool::new(signal.cancel.load(Ordering::Acquire)));
        let relay = deadline::Deadline::forward_cancel(Arc::clone(signal), Arc::clone(&cancel))?;
        let runtime = verification::runtime(installation, home, config, cancel)?;
        Ok(Self {
            runtime,
            _cancel: relay,
        })
    }
}
impl Drop for PrivateRuntime {
    fn drop(&mut self) {
        self.runtime.close();
    }
}
