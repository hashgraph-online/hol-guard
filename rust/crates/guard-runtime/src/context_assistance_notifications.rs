//! Optional native-only notification mailbox. Neither producer waits for the
//! SDK, reads sources, takes evidence acknowledgements or changes a decision.
use guard_context_assistance::{ContextDocument, RuntimeError};
use guard_contracts::{GuardHookEnvelopeV2, NativeHookDecisionReceiptV1};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock, Weak,
};

const ORIGINS: usize = 128;
const READY: usize = 64;
pub(crate) const WINDOW: usize = 16;

#[derive(Clone)]
pub(crate) struct ReceiptFact {
    pub(crate) workspace: PathBuf,
    pub(crate) harness: String,
    pub(crate) decision_id: String,
    event: String,
    decision: String,
    policy_action: String,
    observed_policy_action: String,
    observe_mode: bool,
    generation: u64,
}
impl ReceiptFact {
    pub(crate) fn document(&self) -> ContextDocument {
        ContextDocument { id: format!("receipt:{}", self.decision_id), start_line: 1,
            text: format!("Guard recorded decision '{}' for {} in {} at policy generation {}. Recorded policy action: {}; observed policy action: {}; observe mode: {}. Native receipt {}. This is a recorded decision, not execution confirmation or an approval grant.",
                self.decision, self.event, self.harness, self.generation, self.policy_action, self.observed_policy_action, self.observe_mode, self.decision_id) }
    }
}
struct Origin {
    fact: ReceiptFact,
    proof: String,
}
#[derive(Default)]
struct Inbox {
    origins: BTreeMap<String, Origin>,
    order: VecDeque<String>,
    ready: VecDeque<ReceiptFact>,
}
pub(crate) struct Batch {
    pub(crate) facts: Vec<ReceiptFact>,
    pub(crate) dropped: u64,
    pub(crate) epoch: Epoch,
}
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct Epoch {
    local: u64,
    global_loss: u64,
}
pub(crate) struct Notifications {
    pub(crate) actions: crate::context_assistance_action_facts::Actions,
    capture_actions: bool,
    capture_receipts: bool,
    inbox: Mutex<Inbox>,
    epoch: AtomicU64,
    lost: AtomicU64,
    closed: AtomicBool,
    observed_loss: AtomicU64,
}
static GLOBAL_LOSS: AtomicU64 = AtomicU64::new(0);
impl Default for Notifications {
    fn default() -> Self {
        Self {
            actions: Default::default(),
            capture_actions: false,
            capture_receipts: true,
            inbox: Mutex::default(),
            epoch: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            observed_loss: AtomicU64::new(GLOBAL_LOSS.load(Ordering::Acquire)),
        }
    }
}
/// A producer never waits for optional state. A missed delivery invalidates
/// every active observer conservatively, without allocating on the off path.
pub(crate) fn missed_origin() {
    GLOBAL_LOSS.fetch_add(1, Ordering::AcqRel);
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn policy_action(value: Option<&str>) -> Option<&str> {
    match value {
        None => Some("not recorded"),
        Some(value)
            if [
                "allow",
                "warn",
                "review",
                "require-reapproval",
                "sandbox-required",
                "block",
            ]
            .contains(&value) =>
        {
            Some(value)
        }
        _ => None,
    }
}
impl Notifications {
    pub(crate) fn with_sources(capture_actions: bool, capture_receipts: bool) -> Self {
        Self {
            capture_actions,
            capture_receipts,
            ..Self::default()
        }
    }
    pub(crate) fn close(&self) {
        self.actions.close();
        self.closed.store(true, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn clear(&self) -> Result<(), RuntimeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        let mut inbox = self.inbox.try_lock().map_err(|_| RuntimeError::Busy)?;
        self.actions.clear()?;
        *inbox = Inbox::default();
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    pub(crate) fn epoch(&self) -> Epoch {
        Epoch {
            local: self.epoch.load(Ordering::Acquire),
            global_loss: GLOBAL_LOSS.load(Ordering::Acquire),
        }
    }
    fn lost(&self) {
        self.lost.fetch_add(1, Ordering::Relaxed);
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }
    /// Called only immediately after native origin authentication. The SDK
    /// projection comes from this typed native value, never a persisted caller
    /// mapping. The origin authenticator stays in this private mailbox.
    pub(crate) fn native_origin(&self, workspace: &str, receipt: &NativeHookDecisionReceiptV1) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Some(proof) = receipt.origin_authentication.as_ref().filter(|p| digest(p)) else {
            return;
        };
        let (Some(policy_action), Some(observed_policy_action)) = (
            policy_action(receipt.policy_action.as_deref()),
            policy_action(receipt.observed_policy_action.as_deref()),
        ) else {
            return;
        };
        let path = Path::new(workspace);
        if workspace.len() > 4096
            || !path.is_absolute()
            || path.components().any(|p| matches!(p, Component::ParentDir))
            || !digest(&receipt.decision_id)
            || crate::guard_config_harness::canonical_harness_id(&receipt.harness)
                != Some(receipt.harness.as_str())
            || !["PreToolUse", "PostToolUse", "UserPromptSubmit"]
                .contains(&receipt.event_name.as_str())
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
        {
            return;
        }
        let Ok(mut inbox) = self.inbox.try_lock() else {
            self.lost();
            return;
        };
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        inbox.order.retain(|id| id != &receipt.decision_id);
        if inbox.origins.len() >= ORIGINS && !inbox.origins.contains_key(&receipt.decision_id) {
            if let Some(oldest) = inbox.order.pop_front() {
                inbox.origins.remove(&oldest);
                self.lost();
            }
        }
        inbox.order.push_back(receipt.decision_id.clone());
        inbox.origins.insert(
            receipt.decision_id.clone(),
            Origin {
                fact: ReceiptFact {
                    workspace: path.into(),
                    harness: receipt.harness.clone(),
                    decision_id: receipt.decision_id.clone(),
                    event: receipt.event_name.clone(),
                    decision: receipt.decision.clone(),
                    policy_action: policy_action.into(),
                    observed_policy_action: observed_policy_action.into(),
                    observe_mode: receipt.observe_mode,
                    generation: receipt.policy_generation,
                },
                proof: proof.clone(),
            },
        );
    }
    /// Called after successful native persistence. A matching native origin
    /// must already exist. Extra/untrusted receipt fields never become text.
    fn persisted(&self, receipt: &Map<String, Value>) {
        if self.closed.load(Ordering::Acquire) || !self.capture_receipts {
            return;
        }
        let (Some(id), Some(proof)) = (
            receipt.get("decision_id").and_then(Value::as_str),
            receipt.get("origin_authentication").and_then(Value::as_str),
        ) else {
            return;
        };
        let Ok(mut inbox) = self.inbox.try_lock() else {
            self.lost();
            return;
        };
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if inbox
            .origins
            .get(id)
            .is_none_or(|origin| origin.proof != proof)
        {
            return;
        }
        let origin = inbox.origins.remove(id).expect("origin checked above");
        inbox.order.retain(|key| key != id);
        if inbox.ready.len() >= READY {
            inbox.ready.pop_front();
            self.lost();
        }
        inbox.ready.push_back(origin.fact);
    }
    pub(crate) fn current(
        &self,
        epoch: Epoch,
        scope: Option<(&Path, &str)>,
    ) -> Result<(), RuntimeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        let inbox = self.inbox.try_lock().map_err(|_| RuntimeError::Busy)?;
        if self.epoch() != epoch
            || inbox.ready.iter().any(|fact| {
                scope.is_none_or(|(workspace, app)| {
                    fact.workspace == workspace && (app == "dashboard" || app == fact.harness)
                })
            })
        {
            return Err(RuntimeError::ContextStale);
        }
        Ok(())
    }
    pub(crate) fn drain(&self) -> Result<Batch, RuntimeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        let mut inbox = self.inbox.try_lock().map_err(|_| RuntimeError::Busy)?;
        // Capture the fence before draining. A producer that loses a race
        // after this point makes the read stale, even if its loss count was
        // already included in this batch.
        let epoch = self.epoch();
        let previous = self.observed_loss.swap(epoch.global_loss, Ordering::AcqRel);
        Ok(Batch {
            facts: inbox.ready.drain(..).collect(),
            dropped: self
                .lost
                .swap(0, Ordering::AcqRel)
                .saturating_add(epoch.global_loss.saturating_sub(previous)),
            epoch,
        })
    }
}

type Registry = Mutex<BTreeMap<PathBuf, Weak<Notifications>>>;
static REGISTRY: OnceLock<Registry> = OnceLock::new();
pub(crate) fn register(home: PathBuf, notifications: &Arc<Notifications>) -> bool {
    let registry = REGISTRY.get_or_init(Default::default);
    let Ok(mut registry) = registry.try_lock() else {
        return false;
    };
    registry.retain(|_, observer| observer.strong_count() > 0);
    if registry.len() >= 64 && !registry.contains_key(&home) {
        return false;
    }
    registry.insert(home, Arc::downgrade(notifications));
    true
}
fn observer(home: &Path) -> Option<Arc<Notifications>> {
    // No registry allocation, file read or SDK activity on the default off path.
    let registry = REGISTRY.get()?;
    let Ok(registry) = registry.try_lock() else {
        missed_origin();
        return None;
    };
    let observer = registry.get(home).and_then(Weak::upgrade);
    drop(registry);
    observer
}
pub(crate) fn notify_hook(
    envelope: &GuardHookEnvelopeV2,
    receipt: &NativeHookDecisionReceiptV1,
    result: &Value,
) {
    native_origin(
        Path::new(&envelope.source.guard_home),
        envelope.source.cwd.as_deref(),
        receipt,
        result,
    );
}
pub(crate) fn native_origin(
    home: &Path,
    workspace: Option<&str>,
    receipt: &NativeHookDecisionReceiptV1,
    result: &Value,
) {
    let Some(workspace) = workspace else {
        return;
    };
    if let Some(observer) = observer(home) {
        if observer.capture_receipts {
            observer.native_origin(workspace, receipt);
        }
        if observer.capture_actions {
            if let Some(action) = result
                .get("action")
                .and_then(|value| serde_json::from_value(value.clone()).ok())
            {
                observer.actions.capture(workspace, receipt, action);
            }
        }
    }
}
pub(crate) fn persisted(home: &Path, receipt: &Map<String, Value>) {
    if let Some(observer) = observer(home) {
        observer.persisted(receipt);
    }
}

#[cfg(test)]
#[path = "context_assistance_notifications_tests.rs"]
mod tests;
