//! Optional native association data. It never supplies launch authorization.
//! No SDK handle or process owner survives into the native policy fence.
#[cfg(any(target_os = "macos", test))]
use guard_context_assistance::ContextFence;
#[cfg(target_os = "macos")]
use guard_context_assistance::{BrokerExecutionHandoff, RuntimeActivity};
use serde_json::{json, Value};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
#[cfg(target_os = "macos")]
use std::sync::Arc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "macos", test))]
const CAPACITY: usize = 32;
const RETENTION: Duration = Duration::from_secs(300);

#[derive(Default)]
pub(crate) struct Observations {
    entries: Mutex<VecDeque<(Instant, Value)>>,
    closed: AtomicBool,
}
impl Observations {
    #[cfg(any(target_os = "macos", test))]
    fn record(&self, value: Value, scope: Option<&ContextFence>) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut entries) = self.entries.try_lock() else {
            return;
        };
        if self.closed.load(Ordering::Acquire) || scope.is_some_and(|scope| !scope.is_current()) {
            return;
        }
        let now = Instant::now();
        entries.retain(|(at, old)| {
            now.duration_since(*at) < RETENTION && old["effect_id"] != value["effect_id"]
        });
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back((now, value));
    }
    pub(crate) fn list(&self) -> Option<Value> {
        if self.closed.load(Ordering::Acquire) {
            return Some(json!([]));
        }
        let mut entries = self.entries.try_lock().ok()?;
        let now = Instant::now();
        entries.retain(|(at, _)| now.duration_since(*at) < RETENTION);
        if self.closed.load(Ordering::Acquire) {
            return Some(json!([]));
        }
        Some(Value::Array(
            entries.iter().rev().map(|(_, v)| v.clone()).collect(),
        ))
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut entries) = self.entries.try_lock() {
            entries.clear();
        }
    }
    pub(crate) fn forget_scope(&self, scope: &str) -> Result<(), String> {
        self.entries
            .lock()
            .map_err(|_| "native_context_assistance_history_unavailable")?
            .retain(|(_, value)| value["scope_id"] != scope);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub(crate) struct Checked {
    pub(crate) facts: crate::native_exact_action_op::bash_context::Facts,
    pub(crate) handoff: BrokerExecutionHandoff,
    pub(crate) scope_id: String,
    pub(crate) scope: ContextFence,
}

#[cfg(target_os = "macos")]
pub(crate) struct ExecutionContext {
    checked: Checked,
    service: ContextFence,
    activity: RuntimeActivity,
    observations: Arc<Observations>,
    checked_at_ms: Option<u64>,
    barrier_checked_at_ms: Option<u64>,
    reference: Option<String>,
    valid: bool,
    dispatched: bool,
    finished: bool,
    reason: Option<&'static str>,
}

#[cfg(target_os = "macos")]
impl ExecutionContext {
    pub(crate) fn new(
        checked: Checked,
        service: ContextFence,
        activity: RuntimeActivity,
        observations: Arc<Observations>,
    ) -> Option<Self> {
        if checked.handoff.effect_id() != checked.facts.effect_id
            || checked.handoff.intent_digest() != checked.facts.sdk_intent
        {
            return None;
        }
        Some(Self {
            checked,
            service,
            activity,
            observations,
            checked_at_ms: now_ms(),
            barrier_checked_at_ms: None,
            reference: None,
            valid: true,
            dispatched: false,
            finished: false,
            reason: None,
        })
    }
    pub(crate) fn require_native_binding(&mut self, artifact: &str, generation: u64, policy: &str) {
        if self.checked.facts.artifact_hash != artifact
            || self.checked.facts.policy_generation != generation
            || self.checked.facts.policy_digest != policy
        {
            self.valid = false;
            self.reason = Some("captured_native_binding_changed");
        }
    }
    pub(crate) fn associate_invocation(&mut self, native_operation: &str) {
        // The real journal allocator supplies this physical invocation. It is
        // never a caller's assertion that an SDK effect has been dispatched.
        self.reference = Some(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&json!([native_operation, self.checked.facts.artifact_hash]))
                    .expect("fixed native tuple serializes")
            )
        ));
        self.record("prepared");
    }
    pub(crate) fn poll_at_barrier(&mut self) {
        self.barrier_checked_at_ms = now_ms();
        if !self.service.is_current()
            || !self.checked.scope.is_current()
            || !self.activity.is_active()
            || Instant::now() >= self.checked.facts.expires
        {
            self.valid = false;
            self.reason = Some("context_revoked_expired_or_unavailable");
        }
    }
    pub(crate) fn replayed(&mut self) {
        self.valid = false;
        self.reason = Some("native_operation_already_recorded");
        self.finished = true;
        self.record("not_dispatched");
    }
    pub(crate) fn dispatched(&mut self) {
        self.dispatched = true;
        self.record("dispatch_acknowledged");
    }
    pub(crate) fn completed(&mut self) {
        self.finished = true;
        self.record("completed");
    }
    pub(crate) fn uncertain(&mut self) {
        self.finished = true;
        self.record("outcome_unknown");
    }
    fn record(&self, phase: &'static str) {
        if !self.service.is_current() || !self.checked.scope.is_current() {
            return;
        }
        let sdk = self.checked.handoff.metadata();
        self.observations.record(
            json!({
                "schema":"guard-cigar-native-execution-observation.v1", "data_role":true,
                "effect_id":self.checked.handoff.effect_id(), "snapshot_id":sdk["snapshot_id"],
                "scope_id":self.checked.scope_id, "execution_reference":self.reference,
                "phase":phase, "source_qualification":"captured_native_facts_only",
                "SDK_checked_at_ms":self.checked_at_ms,
                "native_barrier_checked_at_ms":self.barrier_checked_at_ms,
                "context_eligible_at_last_check":self.valid,
                "association_applied":self.dispatched && self.valid,
                "native_dispatch_acknowledged":self.dispatched,
                "reason":self.reason, "approval_grant":false,
                "send_boundary_atomicity":false,
            }),
            Some(&self.checked.scope),
        );
    }
}

#[cfg(target_os = "macos")]
impl Drop for ExecutionContext {
    fn drop(&mut self) {
        if !self.finished && self.reference.is_some() {
            self.record(if self.dispatched {
                "outcome_unknown"
            } else {
                "not_dispatched"
            });
        }
    }
}

#[cfg(target_os = "macos")]
fn now_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observation_capacity_retention_and_close_never_restore_old_data() {
        let observations = Observations::default();
        for i in 0..CAPACITY + 2 {
            observations.record(json!({"effect_id":i}), None);
        }
        assert_eq!(
            observations.list().unwrap().as_array().unwrap().len(),
            CAPACITY
        );
        observations.entries.lock().unwrap().front_mut().unwrap().0 = Instant::now() - RETENTION;
        assert_eq!(
            observations.list().unwrap().as_array().unwrap().len(),
            CAPACITY - 1
        );
        observations.close();
        observations.record(json!({"effect_id":"cannot-return"}), None);
        assert_eq!(observations.list().unwrap(), json!([]));
    }

    #[test]
    fn revoked_scope_cannot_repopulate_forgotten_observations() {
        let observations = Observations::default();
        let epoch = guard_context_assistance::ContextEpoch::default();
        let fence = epoch.fence();
        let value = json!({"scope_id":"scope:one","effect_id":"effect:one"});
        observations.record(value.clone(), Some(&fence));
        epoch.invalidate();
        observations.forget_scope("scope:one").unwrap();
        observations.record(value, Some(&fence));
        assert_eq!(observations.list().unwrap(), json!([]));
    }
}
