//! Native, process-local invalidation. No serialized value can restore a fence.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

pub struct ContextEpoch(Arc<AtomicU64>);

impl Default for ContextEpoch {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(1)))
    }
}

impl ContextEpoch {
    pub fn fence(&self) -> ContextFence {
        ContextFence {
            epoch: Arc::clone(&self.0),
            expected: self.0.load(Ordering::Acquire),
        }
    }

    pub fn invalidate(&self) {
        // Saturation is permanently unavailable; a wrapped epoch could revive
        // an ancient handle. Release pairs with the launch-side acquire.
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_add(1))
            });
    }
}

impl Drop for ContextEpoch {
    fn drop(&mut self) {
        self.invalidate();
    }
}

pub struct ContextFence {
    epoch: Arc<AtomicU64>,
    expected: u64,
}

impl ContextFence {
    pub fn is_current(&self) -> bool {
        self.expected != u64::MAX && self.epoch.load(Ordering::Acquire) == self.expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidation_drop_and_saturation_never_revive_a_fence() {
        let epoch = ContextEpoch::default();
        let old = epoch.fence();
        assert!(old.is_current());
        epoch.invalidate();
        assert!(!old.is_current());
        let current = epoch.fence();
        assert!(current.is_current());
        epoch.0.store(u64::MAX, Ordering::Release);
        let saturated = epoch.fence();
        epoch.invalidate();
        assert!(!saturated.is_current());
        assert!(!current.is_current());
        let epoch = ContextEpoch::default();
        let dropped = epoch.fence();
        drop(epoch);
        assert!(!dropped.is_current());
    }
}
