//! The evidence writer's `EvidenceStoreApi` seam, answered by the resident's
//! own store ops instead of a Python `GuardStore`.
//!
//! `store_review_event_outbox._native_store_call` is what this replaces: it
//! held the shared storage gate, ran one `GuardStoreRequestV1` through the
//! resident, repaired the store file modes and woke the outbox. None of the
//! evidence methods write the review-event outbox, so the wake has nothing to
//! carry here; the gate hold and the permission repair do, and they follow
//! `mcp_relay_decide_ask`, which already calls store ops in process.
//!
//! Three pieces of this seam sit in sibling modules, because each ports a
//! Python behaviour worth finding on its own:
//! [`crate::hook_evidence_store_gate`] opens and holds the storage gate,
//! [`crate::hook_evidence_store_timeout`] answers the writer's sqlite-timeout
//! seam, and [`crate::hook_evidence_store_wire`] carries the request shapes
//! along with the Python string and truthiness rules the recorded wire
//! depends on.
//!
//! TODO(deps): the native policy barrier stays a seam. Moving provider
//! authority has to be bracketed by `notify_native_policy_mutation`, which
//! walks a registry of in-process Python publisher objects; there is no Rust
//! counterpart to wake, so [`PolicyBarrierApi`] carries it until the snapshot
//! publisher itself is ported.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use guard_command::hook_evidence_writer::{
    ComposioActionSchema, ComposioWorkflowProposal, CorrelationHandle, EvidenceStoreApi,
    ObservedMcpTool,
};
use guard_command::local_supply_chain::utc_now_iso;
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use crate::hook_direct::saved_decision::consume::repair_store_permissions;
use crate::hook_evidence_store_gate::hold_storage_gate;
use crate::hook_evidence_store_timeout::sqlite_timeout_ms;
use crate::hook_evidence_store_wire::{
    evidence_args, fatal_store_code, handle_wire, needs_barrier, python_title, python_truthy,
    request_correlation, store_failure, validated_invocation_preview,
};
use crate::local_store_read::STORE_FILE_NAME;

/// The largest `busy_timeout_ms` `guard_store_op::evaluate` accepts.
const MAX_BUSY_TIMEOUT_MS: u64 = 600_000;

/// `notify_native_policy_mutation(guard_home)` — the native policy barrier.
///
/// A store op that would move policy authority writes nothing and answers
/// `{"need_barrier": true}`; the caller notifies the publishers, repeats the
/// call with `barrier_closed`, and notifies them again.
pub(crate) trait PolicyBarrierApi {
    fn notify_policy_mutation(&self, guard_home: &Path);
}

/// `_notify_legacy_mcp_denial` — notifies on the way in and on the way out,
/// including when the bracketed call fails.
struct PolicyBarrier<'a> {
    barrier: &'a (dyn PolicyBarrierApi + Send + Sync),
    guard_home: &'a Path,
}

impl<'a> PolicyBarrier<'a> {
    fn close(barrier: &'a (dyn PolicyBarrierApi + Send + Sync), guard_home: &'a Path) -> Self {
        barrier.notify_policy_mutation(guard_home);
        Self {
            barrier,
            guard_home,
        }
    }
}

impl Drop for PolicyBarrier<'_> {
    fn drop(&mut self) {
        self.barrier.notify_policy_mutation(self.guard_home);
    }
}

/// The last fatal store failure this seam saw, held for the client that owns
/// recovery.
///
/// `_native_store_call` recovers in place because the caller there holds the
/// `GuardStore` that knows how to quarantine and rebuild one. The resident
/// holds no such object, so it reports the failure instead and the client runs
/// `GuardStore._recover_fatal_sqlite_store`.
///
/// Reporting the failure does not clear it. A reply can be lost after the
/// resident built it, and recovery can fail in the client, so a slot cleared
/// by the read that reported it would lose the failure for good. The signal
/// carries an identifier, the client names that identifier once recovery has
/// run, and only that acknowledgement empties the slot. Recovery stays
/// once-per-failure because the identifier a later request acknowledges is
/// the one the client already handled.
#[derive(Clone, Default)]
pub(crate) struct StoreFatalSignal(Arc<Mutex<Option<PendingFatal>>>);

/// A reported failure and the identifier that clears it.
struct PendingFatal {
    id: String,
    code: &'static str,
}

/// Identifiers are unique within the process, and the counter alone is not
/// enough: a client holding an acknowledgement outlives the resident that
/// issued it, so a restarted resident numbering from one again would see that
/// stale acknowledgement clear a failure the client never recovered from.
/// Every process draws its own nonce, so an identifier from an earlier one is
/// never matched.
static NEXT_FATAL_ID: AtomicU64 = AtomicU64::new(1);
static FATAL_ID_NONCE: OnceLock<String> = OnceLock::new();

/// This process's share of a fatal identifier. A random draw that fails leaves
/// the process with a fixed nonce; the counter still separates failures inside
/// it, which is what the old identifiers gave on their own.
fn fatal_id_nonce() -> &'static str {
    FATAL_ID_NONCE.get_or_init(|| {
        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_err() {
            return "process".to_owned();
        }
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    })
}

impl StoreFatalSignal {
    /// Record `code` unless a failure is already waiting to be acknowledged.
    /// Recovery quarantines and rebuilds the whole store, so a second failure
    /// behind the first is handled by the recovery the first one asks for.
    pub(crate) fn record(&self, code: &'static str) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_none() {
            let id = NEXT_FATAL_ID.fetch_add(1, Ordering::Relaxed);
            *slot = Some(PendingFatal {
                id: format!("fatal-{}-{id}", fatal_id_nonce()),
                code,
            });
        }
    }

    /// The pending failure as the wire carries it, left in the slot.
    pub(crate) fn peek(&self) -> Value {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map_or(
                Value::Null,
                |pending| json!({ "id": pending.id, "code": pending.code }),
            )
    }

    /// Take `other`'s pending failure when this signal has none.
    ///
    /// A writer whose thread has exited is replaced, and the failure it was
    /// still waiting to report would go with it. The replacement carries it
    /// instead, identifier and all, so an acknowledgement the client is
    /// already sending still clears the failure it recovered from.
    pub(crate) fn adopt(&self, other: &StoreFatalSignal) {
        let taken = other
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(pending) = taken else {
            return;
        };
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_none() {
            *slot = Some(pending);
        }
    }

    /// Drop the pending failure when `id` names it. An acknowledgement for a
    /// failure that has already been replaced leaves the newer one waiting.
    pub(crate) fn acknowledge(&self, id: &str) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.as_ref().is_some_and(|pending| pending.id == id) {
            *slot = None;
        }
    }
}

/// The writer's store seam, bound to one installation's Guard home.
pub(crate) struct NativeEvidenceStore {
    guard_home: PathBuf,
    /// `GuardStore.guard_source`, echoed into every request.
    source: String,
    barrier: Box<dyn PolicyBarrierApi + Send + Sync>,
    fatal: StoreFatalSignal,
}

impl NativeEvidenceStore {
    pub(crate) fn new(
        guard_home: PathBuf,
        source: &str,
        barrier: Box<dyn PolicyBarrierApi + Send + Sync>,
    ) -> Self {
        Self {
            guard_home,
            source: crate::guard_store_approval_write::oauth_source(source),
            barrier,
            fatal: StoreFatalSignal::default(),
        }
    }

    /// The seam's fatal-failure slot, shared with whoever reports it onward.
    pub(crate) fn fatal(&self) -> StoreFatalSignal {
        self.fatal.clone()
    }

    /// One store call under the shared storage gate, with the store files put
    /// back into private mode afterwards.
    ///
    /// A corrupt or failing store is recorded in [`StoreFatalSignal`] on the
    /// way out, so the client that owns the `GuardStore` can quarantine and
    /// rebuild it once rather than letting every later call fail the same way.
    fn call(
        &self,
        request_id: &str,
        method: &str,
        args: Map<String, Value>,
    ) -> Result<Value, io::Error> {
        let timeout_ms = sqlite_timeout_ms();
        let _gate = hold_storage_gate(&self.guard_home, Duration::from_millis(timeout_ms.into()))?;
        // `GuardStoreRequestV1.busy_timeout_ms` is bounded by the resident; a
        // wait longer than that bound still waits here for the gate, and the
        // store's own busy timeout takes the largest value it accepts.
        let busy_timeout_ms = u64::from(timeout_ms).min(MAX_BUSY_TIMEOUT_MS);
        let payload = crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: request_id.to_owned(),
            store_path: self
                .guard_home
                .join(STORE_FILE_NAME)
                .to_string_lossy()
                .into_owned(),
            guard_home: self.guard_home.to_string_lossy().into_owned(),
            method: method.to_owned(),
            source: self.source.clone(),
            busy_timeout_ms,
            args,
        })
        .map(|(payload, _)| payload)
        .map_err(|error| {
            if let Some(code) = fatal_store_code(&error) {
                self.fatal.record(code);
            }
            store_failure(method, &error)
        });
        repair_store_permissions(&self.guard_home);
        payload
    }

    /// A call whose answer the Python wrapper narrows with `bool()`. These
    /// ops answer null for "nothing matched", which is false there too.
    fn call_flag(
        &self,
        request_id: &str,
        method: &str,
        args: Map<String, Value>,
    ) -> Result<bool, io::Error> {
        Ok(python_truthy(&self.call(request_id, method, args)?))
    }
}

impl EvidenceStoreApi for NativeEvidenceStore {
    fn guard_home(&self) -> PathBuf {
        self.guard_home.clone()
    }

    fn is_exact_command_activity_pre_replay(
        &self,
        evidence: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        // `store_command_activity_lifecycle` answers False for evidence that
        // carries no request correlation, without opening the store.
        if request_correlation(evidence).is_none() {
            return Ok(false);
        }
        self.call_flag(
            "hook-evidence-pre-replay",
            "is_exact_command_activity_pre_replay",
            evidence_args(evidence),
        )
    }

    fn record_command_activity(
        &self,
        evidence: &Map<String, Value>,
        invocation_preview: Option<&str>,
    ) -> Result<bool, io::Error> {
        let mut args = evidence_args(evidence);
        args.insert(
            "invocation_preview".to_owned(),
            match validated_invocation_preview(invocation_preview)? {
                Some(preview) => Value::String(preview),
                None => Value::Null,
            },
        );
        // The writer records the decided command, never a shadow evaluation,
        // so both shadow arguments carry their Python defaults.
        args.insert("shadow".to_owned(), Value::Null);
        args.insert("shadow_evaluation_succeeded".to_owned(), Value::Bool(false));
        self.call_flag(
            "hook-evidence-command-activity",
            "record_command_activity",
            args,
        )
    }

    fn record_composio_discovery(
        &self,
        source: &ObservedMcpTool,
        actions: &[ComposioActionSchema],
        seen_at: &str,
        proposals: &[ComposioWorkflowProposal],
    ) -> Result<(), io::Error> {
        let cli_id = self.ensure_local_mcp_observation(source, seen_at)?;
        let mut args = Map::new();
        args.insert("cli_id".to_owned(), Value::String(cli_id));
        args.insert(
            "identity_hash".to_owned(),
            Value::String(source.server.identity_hash.clone()),
        );
        args.insert(
            "server_command".to_owned(),
            match &source.server.command {
                Some(command) => Value::String(command.clone()),
                None => Value::Null,
            },
        );
        args.insert(
            "source_tool".to_owned(),
            Value::String(source.qualified_name.clone()),
        );
        args.insert("seen_at".to_owned(), Value::String(seen_at.to_owned()));
        args.insert(
            "actions".to_owned(),
            Value::Array(
                actions
                    .iter()
                    .map(|action| {
                        json!({
                            "toolkit": action.toolkit,
                            "tool_slug": action.tool_slug,
                            "description": action.description,
                            "input_schema": Value::Object(action.input_schema.clone()),
                            "full_schema": action.full_schema,
                        })
                    })
                    .collect(),
            ),
        );
        args.insert(
            "proposals".to_owned(),
            Value::Array(
                proposals
                    .iter()
                    .map(|proposal| {
                        json!({
                            "primary": proposal.primary,
                            "supporting": proposal.supporting,
                            "guidance_present": proposal.guidance_present,
                        })
                    })
                    .collect(),
            ),
        );
        let answer = self.call(
            "hook-evidence-composio-discovery",
            "record_composio_discovery",
            args.clone(),
        )?;
        if needs_barrier(&answer) {
            // This batch moves the provider authority, so it has to run inside
            // the barrier the resident cannot close for itself.
            let _barrier = PolicyBarrier::close(self.barrier.as_ref(), &self.guard_home);
            args.insert("barrier_closed".to_owned(), Value::Bool(true));
            self.call(
                "hook-evidence-composio-discovery-barrier",
                "record_composio_discovery",
                args,
            )?;
        }
        Ok(())
    }

    fn record_native_decision_receipt(
        &self,
        receipt: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        // `_receipt_wire` — the op parses the text itself, so a receipt that
        // cannot be serialized never reaches the store.
        let wire = serde_json::to_string(&Value::Object(receipt.clone())).map_err(|error| {
            io::Error::other(format!("invalid native decision receipt: {error}"))
        })?;
        let mut args = Map::new();
        args.insert("receipt".to_owned(), Value::String(wire));
        // Python stamps `datetime.now(timezone.utc).isoformat()`; so does
        // `utc_now_iso`, down to the microsecond. Callers open their recent
        // windows with a Python clock and compare this column as text, so a
        // coarser stamp here would read as older than the window it belongs
        // to.
        args.insert("now".to_owned(), Value::String(utc_now_iso()));
        self.call(
            "hook-evidence-receipt",
            "record_native_decision_receipt",
            args,
        )?;
        // `store_native_decision_receipts.record_native_decision_receipt`
        // always answers True: an insert the store ignored as a duplicate is
        // still a receipt the writer has nothing left to do about.
        Ok(true)
    }

    fn command_activity_by_request_correlation(
        &self,
        correlation: &CorrelationHandle,
    ) -> Result<Option<Map<String, Value>>, io::Error> {
        let mut args = Map::new();
        args.insert("correlation".to_owned(), handle_wire(correlation));
        match self.call(
            "hook-evidence-activity-by-correlation",
            "command_activity_by_request_correlation",
            args,
        )? {
            Value::Null => Ok(None),
            Value::Object(row) => Ok(Some(row)),
            other => Err(io::Error::other(format!(
                "command_activity_by_request_correlation: expected a row, got {other}"
            ))),
        }
    }

    fn transition_command_activity(&self, current: &Map<String, Value>) -> Result<bool, io::Error> {
        let mut args = Map::new();
        args.insert("current".to_owned(), Value::Object(current.clone()));
        self.call_flag(
            "hook-evidence-activity-transition",
            "transition_command_activity",
            args,
        )
    }

    fn record_command_activity_observation_conflict(
        &self,
        occurred_at: &str,
    ) -> Result<(), io::Error> {
        let mut args = Map::new();
        args.insert(
            "occurred_at".to_owned(),
            Value::String(occurred_at.to_owned()),
        );
        self.call(
            "hook-evidence-observation-conflict",
            "record_command_activity_observation_conflict",
            args,
        )?;
        Ok(())
    }
}

impl NativeEvidenceStore {
    /// `store_local_mcp.ensure_local_mcp_observation` — the connection grant
    /// the catalog write is held against, bound before any metadata is
    /// written. It carries its own barrier retry: adopting a legacy denial
    /// moves policy authority too.
    fn ensure_local_mcp_observation(
        &self,
        source: &ObservedMcpTool,
        seen_at: &str,
    ) -> Result<String, io::Error> {
        let identity = &source.identity;
        let mut args = Map::new();
        args.insert("cli_id".to_owned(), Value::String(identity.cli_id.clone()));
        args.insert(
            "identity_hash".to_owned(),
            Value::String(identity.identity_hash.clone()),
        );
        args.insert("kind".to_owned(), Value::String(identity.kind.clone()));
        args.insert("name".to_owned(), Value::String(identity.name.clone()));
        args.insert(
            "interpreter_name".to_owned(),
            match &identity.interpreter_name {
                Some(name) => Value::String(name.clone()),
                None => Value::Null,
            },
        );
        args.insert(
            "example_label".to_owned(),
            Value::String(identity.example_label.clone()),
        );
        args.insert("seen_at".to_owned(), Value::String(seen_at.to_owned()));
        args.insert(
            "server_identity_hash".to_owned(),
            Value::String(source.server.identity_hash.clone()),
        );
        args.insert(
            "server_command".to_owned(),
            match &source.server.command {
                Some(command) => Value::String(command.clone()),
                None => Value::Null,
            },
        );
        args.insert(
            "server_args_hash".to_owned(),
            Value::String(source.server.args_hash.clone()),
        );
        args.insert(
            "source_label".to_owned(),
            Value::String(format!(
                "{} · observed provider metadata",
                python_title(&source.harness)
            )),
        );
        args.insert("connection_identity_hash".to_owned(), Value::Null);
        args.insert("replayed".to_owned(), Value::Bool(false));
        args.insert("replay_now".to_owned(), Value::Null);
        args.insert("clock".to_owned(), Value::String(utc_now_iso()));
        let mut answer = self.call(
            "hook-evidence-mcp-observation",
            "ensure_local_mcp_observation",
            args.clone(),
        )?;
        if needs_barrier(&answer) {
            let _barrier = PolicyBarrier::close(self.barrier.as_ref(), &self.guard_home);
            args.insert("barrier_closed".to_owned(), Value::Bool(true));
            answer = self.call(
                "hook-evidence-mcp-observation-barrier",
                "ensure_local_mcp_observation",
                args,
            )?;
        }
        match answer.get("cli_id") {
            Some(Value::String(cli_id)) => Ok(cli_id.clone()),
            // `LocalCliReplaySkippedError` cannot happen here — this call
            // never replays — so every other answer is the store returning a
            // shape its own contract rules out.
            _ => Err(io::Error::other(
                "ensure_local_mcp_observation: native_local_mcp_observation_invalid",
            )),
        }
    }
}

#[cfg(test)]
#[path = "hook_evidence_store_tests.rs"]
mod tests;
