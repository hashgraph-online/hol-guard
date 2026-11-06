use super::{
    outcome_code, outcome_slot, DirectHookCounters, HarnessSlot, HARNESS_NAMES, HARNESS_SLOTS,
    OTHER_HARNESS, OUTCOMES, OUTCOME_SLOTS,
};
use crate::hook_direct::{HookDirectDefer, DIRECT_HARNESSES};
use crate::hook_direct_evidence::{drain, DirectEvidenceQueue, HookDirectEvidenceDrainRequestV1};
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[test]
fn every_harness_name_has_its_own_slot() {
    let names: BTreeSet<&str> = HARNESS_NAMES.iter().copied().collect();
    assert_eq!(names.len(), HARNESS_SLOTS);
    for (slot, name) in HARNESS_NAMES.iter().enumerate().take(OTHER_HARNESS) {
        assert_eq!(HarnessSlot::of(name), HarnessSlot(slot), "{name}");
    }
    for harness in DIRECT_HARNESSES {
        assert_ne!(
            HarnessSlot::of(harness),
            HarnessSlot(OTHER_HARNESS),
            "{harness}"
        );
    }
    assert_eq!(DIRECT_HARNESSES.len(), OTHER_HARNESS);
}

#[test]
fn any_other_harness_string_counts_as_other() {
    for harness in ["", "gemini", "Codex", "codex ", "/usr/bin/codex", "other"] {
        assert_eq!(
            HarnessSlot::of(harness),
            HarnessSlot(OTHER_HARNESS),
            "{harness:?}"
        );
    }
}

#[test]
fn every_outcome_has_its_own_slot_and_code() {
    assert_eq!(OUTCOMES.len(), OUTCOME_SLOTS);
    let mut codes = BTreeSet::new();
    for (slot, outcome) in OUTCOMES.iter().enumerate() {
        assert_eq!(outcome_slot(*outcome), slot, "{outcome:?}");
        assert!(codes.insert(outcome_code(*outcome)), "{outcome:?}");
    }
    assert_eq!(outcome_code(None), "answer");
    assert_eq!(
        outcome_code(Some(HookDirectDefer::Lane(
            DirectLaneDefer::WorkspaceUnknown
        ))),
        "direct_lane_workspace_unknown"
    );
}

#[test]
fn a_snapshot_names_only_the_nonzero_counts() {
    let counters = DirectHookCounters::default();
    assert_eq!(counters.snapshot(), json!({ "by_harness": {} }));
    let lane = Some(HookDirectDefer::Lane(DirectLaneDefer::WorkspaceUnknown));
    counters.record(HarnessSlot::of("codex"), None);
    counters.record(HarnessSlot::of("codex"), None);
    counters.record(HarnessSlot::of("codex"), lane);
    counters.record(
        HarnessSlot::of("gemini"),
        Some(HookDirectDefer::HarnessUnsupported),
    );
    assert_eq!(
        counters.snapshot(),
        json!({ "by_harness": {
            "codex": { "answer": 2, "direct_lane_workspace_unknown": 1 },
            "other": { "direct_hook_harness_unsupported": 1 },
        }})
    );
}

#[test]
fn a_drain_page_carries_the_counters_beside_the_records() {
    let queue = DirectEvidenceQueue::default();
    let request = HookDirectEvidenceDrainRequestV1 {
        guard_home: "/guard".to_owned(),
        max_records: None,
        ack_through: None,
        ack_epoch: None,
    };
    let page: Value = serde_json::from_slice(&drain(&request, &queue).unwrap()).unwrap();
    assert_eq!(page["counters"], json!({ "by_harness": {} }));
    assert_eq!(page["records"], json!([]));
    queue
        .counters()
        .record(HarnessSlot::of("cursor"), Some(HookDirectDefer::NotAllow));
    let page: Value = serde_json::from_slice(&drain(&request, &queue).unwrap()).unwrap();
    assert_eq!(
        page["counters"],
        json!({ "by_harness": { "cursor": { "direct_hook_not_allow": 1 } } })
    );
    assert_eq!(page["schema"], "guard-hook-direct-evidence.v1");
    assert!(page["epoch"]
        .as_str()
        .is_some_and(|epoch| !epoch.is_empty()));
}
