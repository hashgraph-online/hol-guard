//! Optional cooperative cancellation; the default archive transports retain
//! their existing behavior. Cancellation never weakens peer/TLS validation.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct CancellableUreqPinnedTransport {
    pub cancel: Arc<AtomicBool>,
}
pub(super) fn cancelled() -> RestrictedDownloadError {
    RestrictedDownloadError::new(
        "external_archive_cancelled",
        "External archive transfer was cancelled.",
    )
}
impl PinnedHttpsTransport for CancellableUreqPinnedTransport {
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(cancelled());
        }
        open_pinned(
            destination,
            address,
            deadline,
            None,
            Some(Arc::clone(&self.cancel)),
        )
    }
}
