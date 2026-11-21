//! Per-resident active launch ownership, separate from durable consent/state.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::PolicySnapshotStore;

// Leave the evaluation pool (at least 16 workers) available for cancellation,
// current policy, and ordinary hooks even while launches wait for their result.
const MAX_ACTIVE: usize = 2;

#[derive(Default)]
struct State {
    stopping: bool,
    active: BTreeMap<String, Arc<AtomicBool>>,
    aliases: BTreeMap<String, Arc<AtomicBool>>,
}

#[derive(Default)]
pub(crate) struct Launches(Mutex<State>);

pub(crate) struct Registration<'owner> {
    owner: &'owner Launches,
    operation_id: &'owner str,
    pub(crate) cancelled: Arc<AtomicBool>,
}

pub(crate) struct Alias<'owner> {
    owner: &'owner Launches,
    operation_id: String,
    cancelled: Arc<AtomicBool>,
}

impl Launches {
    #[cfg(test)]
    pub(crate) fn register<'a>(
        &'a self,
        operation_id: &'a str,
    ) -> Result<Registration<'a>, String> {
        self.register_with_cancellation(operation_id, Arc::new(AtomicBool::new(false)))
    }

    pub(crate) fn register_with_cancellation<'a>(
        &'a self,
        operation_id: &'a str,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Registration<'a>, String> {
        if !guard_contracts::native_bash_operation_id_is_valid(operation_id) {
            return Err("native_bash_operation_id_invalid".into());
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| "native_bash_cancellation_unavailable")?;
        if state.stopping {
            return Err("native_bash_launch_owner_stopping".into());
        }
        if state.active.contains_key(operation_id) || state.aliases.contains_key(operation_id) {
            return Err("native_bash_operation_active".into());
        }
        if state.active.len() >= MAX_ACTIVE {
            return Err("native_bash_launch_capacity".into());
        }
        state
            .active
            .insert(operation_id.into(), Arc::clone(&cancelled));
        Ok(Registration {
            owner: self,
            operation_id,
            cancelled,
        })
    }

    /// The native allocator binds a journal identity to the existing owning
    /// transport. Both names cancel the same run; aliases do not add capacity.
    pub(crate) fn alias(
        &self,
        base_id: &str,
        operation_id: &str,
    ) -> Result<Option<Alias<'_>>, String> {
        if base_id == operation_id {
            return Ok(None);
        }
        if !guard_contracts::native_bash_operation_id_is_valid(operation_id) {
            return Err("native_bash_operation_id_invalid".into());
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| "native_bash_cancellation_unavailable")?;
        let Some(cancelled) = state.active.get(base_id).cloned() else {
            return Ok(None);
        };
        if state.stopping
            || state.active.contains_key(operation_id)
            || state.aliases.contains_key(operation_id)
        {
            return Err("native_bash_operation_active".into());
        }
        state
            .aliases
            .insert(operation_id.into(), Arc::clone(&cancelled));
        Ok(Some(Alias {
            owner: self,
            operation_id: operation_id.into(),
            cancelled,
        }))
    }

    #[cfg(test)]
    pub(crate) fn active_cancellation(&self, operation_id: &str) -> Option<Arc<AtomicBool>> {
        self.0.lock().unwrap().active.get(operation_id).cloned()
    }

    pub(crate) fn cancel(&self, operation_id: &str) -> Result<bool, String> {
        let state = self
            .0
            .lock()
            .map_err(|_| "native_bash_cancellation_unavailable")?;
        let cancellation = state
            .active
            .get(operation_id)
            .or_else(|| state.aliases.get(operation_id));
        if let Some(cancellation) = cancellation {
            cancellation.store(true, Ordering::Release);
        }
        Ok(cancellation.is_some())
    }

    pub(crate) fn activity(&self, operation_id: &str) -> Result<(bool, bool), String> {
        if !guard_contracts::native_bash_operation_id_is_valid(operation_id) {
            return Err("native_bash_operation_id_invalid".into());
        }
        let state = self
            .0
            .lock()
            .map_err(|_| "native_bash_cancellation_unavailable")?;
        let cancellation = state
            .active
            .get(operation_id)
            .or_else(|| state.aliases.get(operation_id));
        Ok((
            cancellation.is_some(),
            cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)),
        ))
    }

    pub(crate) fn shutdown(&self) {
        // Poisoning must not leave children running during owner teardown.
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.stopping = true;
        for cancelled in state.active.values() {
            cancelled.store(true, Ordering::Release);
        }
    }
}

impl Drop for Launches {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state
            .active
            .get(self.operation_id)
            .is_some_and(|flag| Arc::ptr_eq(flag, &self.cancelled))
        {
            state.active.remove(self.operation_id);
            state
                .aliases
                .retain(|_, flag| !Arc::ptr_eq(flag, &self.cancelled));
        }
    }
}

impl Drop for Alias<'_> {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state
            .aliases
            .get(&self.operation_id)
            .is_some_and(|flag| Arc::ptr_eq(flag, &self.cancelled))
        {
            state.aliases.remove(&self.operation_id);
        }
    }
}

impl PolicySnapshotStore {
    pub(crate) fn bash_launches(&self) -> &Launches {
        &self.bash_launches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_invocation_alias_shares_cancellation_and_cannot_outlive_owner() {
        let owner = Launches::default();
        let registration = owner.register("sdk-operation-base-0001").unwrap();
        let alias = owner
            .alias("sdk-operation-base-0001", "native-invocation-0001")
            .unwrap()
            .unwrap();
        assert_eq!(
            owner.activity("native-invocation-0001").unwrap(),
            (true, false)
        );
        assert!(owner.register("native-invocation-0001").is_err());
        assert!(owner
            .alias("sdk-operation-base-0001", "native-invocation-0001")
            .is_err());
        let second = owner.register("sdk-operation-base-0002").unwrap();
        assert!(owner.cancel("native-invocation-0001").unwrap());
        assert!(registration.cancelled.load(Ordering::Acquire));
        assert!(!second.cancelled.load(Ordering::Acquire));
        drop(registration);
        assert_eq!(
            owner.activity("native-invocation-0001").unwrap(),
            (false, false)
        );
        let replacement = owner.register("sdk-operation-base-0001").unwrap();
        let replacement_alias = owner
            .alias("sdk-operation-base-0001", "native-invocation-0001")
            .unwrap()
            .unwrap();
        drop(alias);
        assert_eq!(
            owner.activity("native-invocation-0001").unwrap(),
            (true, false)
        );
        drop(replacement_alias);
        assert_eq!(
            owner.activity("native-invocation-0001").unwrap(),
            (false, false)
        );
        assert!(!replacement.cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn registration_is_exclusive_bounded_and_released_on_drop() {
        let owner = Launches::default();
        let first = owner.register("operation-first-0001").unwrap();
        assert_eq!(
            owner.activity("operation-first-0001").unwrap(),
            (true, false)
        );
        assert!(!first.cancelled.load(Ordering::Acquire));
        assert_eq!(
            owner.activity("operation-unknown-0004").unwrap(),
            (false, false)
        );
        assert!(owner.activity("invalid").is_err());
        assert!(owner.register("operation-first-0001").is_err());
        let second = owner.register("operation-second-0002").unwrap();
        assert!(owner.register("operation-third-0003").is_err());
        assert!(!owner.cancel("operation-unknown-0004").unwrap());
        assert!(owner.cancel("operation-first-0001").unwrap());
        assert!(first.cancelled.load(Ordering::Acquire));
        assert_eq!(
            owner.activity("operation-first-0001").unwrap(),
            (true, true)
        );
        assert!(!second.cancelled.load(Ordering::Acquire));
        drop(first);
        assert_eq!(
            owner.activity("operation-first-0001").unwrap(),
            (false, false)
        );
        let replacement = owner.register("operation-first-0001").unwrap();
        assert!(!replacement.cancelled.load(Ordering::Acquire));
        owner.shutdown();
        assert!(replacement.cancelled.load(Ordering::Acquire));
        assert!(second.cancelled.load(Ordering::Acquire));
        drop((replacement, second));
        assert!(owner.register("operation-after-shutdown-0005").is_err());
    }
}
