//! Bounded, native-origin decision data. A decision selector never grants
//! source access, proves current executable bytes, or authorizes execution.
use crate::policy_store::PolicySnapshotStore;
use guard_context_assistance::{ContextDocument, RuntimeError};
use guard_contracts::{NativeHookDecisionReceiptV1, PreToolActionV1};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

const CAPACITY: usize = 64;
const TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Policy {
    generation: u64,
    digest: String,
    runtime: String,
}
impl Policy {
    pub(crate) fn current(store: &PolicySnapshotStore) -> Result<Self, String> {
        let snapshot = store.current_snapshot()?;
        Ok(Self {
            generation: snapshot.generation,
            digest: snapshot.policy_digest,
            runtime: snapshot.runtime_identity,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Fact {
    workspace: PathBuf,
    action: PreToolActionV1,
    decision_id: String,
    decision: String,
    policy_action: String,
    observed_policy_action: String,
    observe_mode: bool,
    policy: Policy,
    // These stay native. Keeping the authentic origin and intent prevents a
    // replacement of the same selector from validating a retained context.
    proof: String,
    intent: String,
}
impl Fact {
    pub(crate) fn require_scope(
        &self,
        workspace: &Path,
        app: &str,
        policy: &Policy,
    ) -> Result<(), RuntimeError> {
        if self.workspace == workspace
            && (app == "dashboard" || self.action.harness == app)
            && &self.policy == policy
        {
            Ok(())
        } else {
            Err(RuntimeError::ScopeDenied)
        }
    }
    pub(crate) fn document(&self) -> ContextDocument {
        let kind = serde_json::to_value(self.action.action_type).expect("enum serializes");
        let operation = serde_json::to_value(self.action.operation).expect("enum serializes");
        ContextDocument { id: "guard-action-facts".into(), start_line: 1,
            text: format!("Authenticated native Guard decision {} for {}: action type {}, operation {}, decision {}, policy action {}, policy generation {}. Observed policy action: {}; observe mode: {}. Bounded action: {}; sensitive target: {}. These are native evaluation facts. They do not confirm execution, prove current executable bytes, or grant approval.",
                self.decision_id, self.action.harness, kind, operation, self.decision,
                self.policy_action, self.policy.generation, self.observed_policy_action, self.observe_mode, self.action.bounded, self.action.sensitive_target) }
    }
    pub(crate) fn query(&self) -> String {
        format!("Guard native decision action {:?} operation {:?} {} review policy supporting project guidance", self.action.action_type, self.action.operation, self.decision)
    }
    pub(crate) fn association(&self) -> Value {
        json!({"schema":"guard-context-native-decision.v1", "data_role":true,
            "binding":"authenticated_native_decision", "decision_id":self.decision_id,
            "harness":self.action.harness, "event":self.action.event,
            "action_type":self.action.action_type, "operation":self.action.operation,
            "policy_generation":self.policy.generation.to_string(),
            "execution_binding":"unqualified", "approval_grant":false})
    }
}

#[derive(Default)]
pub(crate) struct Actions {
    entries: Mutex<VecDeque<(Instant, Fact)>>,
    closed: AtomicBool,
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Actions {
    /// Called only at the authenticated native evaluator's producer. This
    /// never waits, reads a file, or contacts CIGAR on the hook path.
    pub(crate) fn capture(
        &self,
        workspace: &str,
        receipt: &NativeHookDecisionReceiptV1,
        action: PreToolActionV1,
    ) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let path = Path::new(workspace);
        let (Some(proof), Some(intent), Some(policy_digest), Some(runtime)) = (
            receipt.origin_authentication.as_deref(),
            receipt.execution_intent_digest.as_deref(),
            receipt.policy_digest.as_deref(),
            receipt.runtime_identity.as_deref(),
        ) else {
            return;
        };
        if workspace.len() > 4096
            || !path.is_absolute()
            || path.components().any(|p| matches!(p, Component::ParentDir))
            || ![proof, intent, &receipt.decision_id, policy_digest, runtime]
                .into_iter()
                .all(digest)
            || receipt.event_name != "PreToolUse"
            || action.event != receipt.event_name
            || action.harness != receipt.harness
            || crate::guard_config_harness::canonical_harness_id(&receipt.harness)
                != Some(receipt.harness.as_str())
            || ![
                "allow",
                "warn",
                "review",
                "require-reapproval",
                "sandbox-required",
                "block",
                "deny",
            ]
            .contains(&receipt.decision.as_str())
            || receipt.policy_action.as_deref().is_some_and(|s| {
                ![
                    "allow",
                    "warn",
                    "review",
                    "require-reapproval",
                    "sandbox-required",
                    "block",
                ]
                .contains(&s)
            })
        {
            return;
        }
        let Ok(mut entries) = self.entries.try_lock() else {
            return;
        };
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let now = Instant::now();
        entries.retain(|(at, fact)| {
            now.duration_since(*at) < TTL && fact.decision_id != receipt.decision_id
        });
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back((
            now,
            Fact {
                workspace: path.into(),
                action,
                decision_id: receipt.decision_id.clone(),
                decision: receipt.decision.clone(),
                policy_action: receipt
                    .policy_action
                    .clone()
                    .unwrap_or_else(|| "not recorded".into()),
                observed_policy_action: receipt
                    .observed_policy_action
                    .as_deref()
                    .filter(|s| {
                        [
                            "allow",
                            "warn",
                            "review",
                            "require-reapproval",
                            "sandbox-required",
                            "block",
                        ]
                        .contains(s)
                    })
                    .unwrap_or("not recorded")
                    .into(),
                observe_mode: receipt.observe_mode,
                policy: Policy {
                    generation: receipt.policy_generation,
                    digest: policy_digest.into(),
                    runtime: runtime.into(),
                },
                proof: proof.into(),
                intent: intent.into(),
            },
        ));
    }
    pub(crate) fn get(&self, decision_id: &str) -> Result<Fact, RuntimeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        if !digest(decision_id) {
            return Err(RuntimeError::RequestInvalid);
        }
        let entries = self.entries.try_lock().map_err(|_| RuntimeError::Busy)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        entries
            .iter()
            .find(|(at, fact)| at.elapsed() < TTL && fact.decision_id == decision_id)
            .map(|(_, fact)| fact.clone())
            .ok_or(RuntimeError::ContextStale)
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut entries) = self.entries.try_lock() {
            entries.clear();
        }
    }
    pub(crate) fn clear(&self) -> Result<(), RuntimeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        self.entries
            .try_lock()
            .map_err(|_| RuntimeError::Busy)?
            .clear();
        Ok(())
    }
}

#[cfg(test)]
#[path = "context_assistance_action_facts_tests.rs"]
mod tests;
