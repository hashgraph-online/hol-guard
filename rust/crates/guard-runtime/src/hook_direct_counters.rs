//! Diagnostic counts of how the resident settled direct hooks.
//!
//! Each direct hook adds one to the cell for its harness and its outcome: an
//! answer, or the reason it deferred to the daemon. The cells are a fixed
//! table of atomics, so counting takes no lock and allocates nothing on the
//! hook path. A harness is counted under one of a fixed set of names, and any
//! other name under `other`; the request's own strings, paths, commands and
//! payloads are never kept.
//!
//! The counts are diagnostics only. Nothing in the resident or the daemon
//! reads them to decide a hook. The daemon receives them on each evidence
//! drain page and logs when they change. They run from the start of the
//! queue whose epoch the page names.

use crate::hook_direct::{HookDirectDefer, HookDirectRequestV1};
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use crate::policy_store::PolicySnapshotStore;
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};

/// The direct harnesses, then `other` for every name outside them.
const HARNESS_NAMES: [&str; HARNESS_SLOTS] = [
    "codex",
    "claude-code",
    "cursor",
    "copilot",
    "kimi",
    "devin",
    "zcode",
    "openclaw",
    "hermes",
    "cline",
    "opencode",
    "grok",
    "pi",
    "omp",
    "other",
];
const HARNESS_SLOTS: usize = 15;
const OTHER_HARNESS: usize = HARNESS_SLOTS - 1;
/// An answer, then every reason a direct hook defers, in slot order.
const OUTCOMES: [Option<HookDirectDefer>; OUTCOME_SLOTS] = [
    None,
    Some(HookDirectDefer::HarnessUnsupported),
    Some(HookDirectDefer::HarnessUnmanaged),
    Some(HookDirectDefer::EventUnsupported),
    Some(HookDirectDefer::PayloadUnsupported),
    Some(HookDirectDefer::TransitionProbe),
    Some(HookDirectDefer::WorkspaceMissing),
    Some(HookDirectDefer::WorkspaceInvalid),
    Some(HookDirectDefer::BindingIncomplete),
    Some(HookDirectDefer::HomeMismatch),
    Some(HookDirectDefer::LocalCliRules),
    Some(HookDirectDefer::PromptNotice),
    Some(HookDirectDefer::PermissionNotice),
    Some(HookDirectDefer::ExecutionEnvironmentInvalid),
    Some(HookDirectDefer::EvidenceUndrained),
    Some(HookDirectDefer::EvidenceFull),
    Some(HookDirectDefer::ContainedRouteFailed),
    Some(HookDirectDefer::EdgeFailed),
    Some(HookDirectDefer::NotAllow),
    Some(HookDirectDefer::SavedDecision),
    Some(HookDirectDefer::ReviewQueue),
    Some(HookDirectDefer::RuntimeSuperseded),
    Some(HookDirectDefer::StructuredMediation),
    Some(HookDirectDefer::Lane(DirectLaneDefer::Unbound)),
    Some(HookDirectDefer::Lane(DirectLaneDefer::SnapshotUnavailable)),
    Some(HookDirectDefer::Lane(DirectLaneDefer::AckMissing)),
    Some(HookDirectDefer::Lane(DirectLaneDefer::AckMismatch)),
    Some(HookDirectDefer::Lane(DirectLaneDefer::AckExpired)),
    Some(HookDirectDefer::Lane(DirectLaneDefer::WorkspaceUnknown)),
    Some(HookDirectDefer::Lane(DirectLaneDefer::InputChanged)),
];
const OUTCOME_SLOTS: usize = 30;
const ANSWER: &str = "answer";

/// The counting slot of a harness name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HarnessSlot(usize);

impl HarnessSlot {
    pub(crate) fn of(harness: &str) -> Self {
        Self(match harness {
            "codex" => 0,
            "claude-code" => 1,
            "cursor" => 2,
            "copilot" => 3,
            "kimi" => 4,
            "devin" => 5,
            "zcode" => 6,
            "openclaw" => 7,
            "hermes" => 8,
            "cline" => 9,
            "opencode" => 10,
            "grok" => 11,
            "pi" => 12,
            "omp" => 13,
            _ => OTHER_HARNESS,
        })
    }
}

fn outcome_slot(outcome: Option<HookDirectDefer>) -> usize {
    let Some(defer) = outcome else {
        return 0;
    };
    match defer {
        HookDirectDefer::HarnessUnsupported => 1,
        HookDirectDefer::HarnessUnmanaged => 2,
        HookDirectDefer::EventUnsupported => 3,
        HookDirectDefer::PayloadUnsupported => 4,
        HookDirectDefer::TransitionProbe => 5,
        HookDirectDefer::WorkspaceMissing => 6,
        HookDirectDefer::WorkspaceInvalid => 7,
        HookDirectDefer::BindingIncomplete => 8,
        HookDirectDefer::HomeMismatch => 9,
        HookDirectDefer::LocalCliRules => 10,
        HookDirectDefer::PromptNotice => 11,
        HookDirectDefer::PermissionNotice => 12,
        HookDirectDefer::ExecutionEnvironmentInvalid => 13,
        HookDirectDefer::EvidenceUndrained => 14,
        HookDirectDefer::EvidenceFull => 15,
        HookDirectDefer::ContainedRouteFailed => 16,
        HookDirectDefer::EdgeFailed => 17,
        HookDirectDefer::NotAllow => 18,
        HookDirectDefer::SavedDecision => 19,
        HookDirectDefer::ReviewQueue => 20,
        HookDirectDefer::RuntimeSuperseded => 21,
        HookDirectDefer::StructuredMediation => 22,
        HookDirectDefer::Lane(lane) => match lane {
            DirectLaneDefer::Unbound => 23,
            DirectLaneDefer::SnapshotUnavailable => 24,
            DirectLaneDefer::AckMissing => 25,
            DirectLaneDefer::AckMismatch => 26,
            DirectLaneDefer::AckExpired => 27,
            DirectLaneDefer::WorkspaceUnknown => 28,
            DirectLaneDefer::InputChanged => 29,
        },
    }
}

fn outcome_code(outcome: Option<HookDirectDefer>) -> &'static str {
    outcome.map_or(ANSWER, HookDirectDefer::code)
}

/// One counter per harness slot and outcome slot.
pub(crate) struct DirectHookCounters {
    cells: [AtomicU64; HARNESS_SLOTS * OUTCOME_SLOTS],
}

impl Default for DirectHookCounters {
    fn default() -> Self {
        Self {
            cells: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl DirectHookCounters {
    pub(crate) fn record(&self, harness: HarnessSlot, outcome: Option<HookDirectDefer>) {
        let cell = harness.0 * OUTCOME_SLOTS + outcome_slot(outcome);
        if let Some(cell) = self.cells.get(cell) {
            cell.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn count(&self, harness: usize, outcome: usize) -> u64 {
        self.cells
            .get(harness * OUTCOME_SLOTS + outcome)
            .map_or(0, |cell| cell.load(Ordering::Relaxed))
    }

    /// The nonzero counts, by harness name and then by outcome code.
    pub(crate) fn snapshot(&self) -> Value {
        let mut by_harness = Map::new();
        for (harness, name) in HARNESS_NAMES.iter().enumerate() {
            let mut outcomes = Map::new();
            for (slot, outcome) in OUTCOMES.iter().enumerate() {
                let count = self.count(harness, slot);
                if count > 0 {
                    outcomes.insert(outcome_code(*outcome).to_owned(), json!(count));
                }
            }
            if !outcomes.is_empty() {
                by_harness.insert((*name).to_owned(), Value::Object(outcomes));
            }
        }
        json!({ "by_harness": by_harness })
    }
}

/// Settle one direct hook with `answer` and count how it was settled.
pub(crate) fn counted(
    request: HookDirectRequestV1,
    policy_store: &PolicySnapshotStore,
    answer: fn(HookDirectRequestV1, &PolicySnapshotStore) -> Result<Value, HookDirectDefer>,
) -> Result<Value, HookDirectDefer> {
    let harness = HarnessSlot::of(&request.harness);
    let outcome = answer(request, policy_store);
    policy_store
        .direct_evidence()
        .counters()
        .record(harness, outcome.as_ref().err().copied());
    outcome
}

#[cfg(test)]
#[path = "hook_direct_counters_tests.rs"]
mod tests;
