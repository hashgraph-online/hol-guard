use super::*;
use serde_json::json;
use std::time::{Duration, Instant};

// These fixtures observe a process-wide loss counter, and the contention
// fixture deliberately advances it. Keep their snapshots independent.
static GLOBAL_LOSS_FIXTURES: Mutex<()> = Mutex::new(());
fn global_loss_fixture() -> std::sync::MutexGuard<'static, ()> {
    GLOBAL_LOSS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

// Typed mailbox fixtures exercise bounded pairing, not receipt authenticity.
// The installed test separately enters through the real native evaluator and
// native evidence writer; production has no caller-facing origin operation.
fn receipt(index: usize) -> NativeHookDecisionReceiptV1 {
    serde_json::from_value(json!({
        "schema":"guard-native-hook-decision-receipt.v1", "version":1, "authority":"rust",
        "decision_id":format!("{index:064x}"), "request_id":"mailbox", "request_digest":"b".repeat(64),
        "harness":"codex", "event_name":"PreToolUse", "payload_kind":"inline", "policy_generation":7,
        "policy_digest":"c".repeat(64), "rule_digest":"d".repeat(64), "runtime_identity":"e".repeat(64),
        "decision":"review", "model_output_action":"allow", "policy_action":"review", "observed_policy_action":null,
        "reason_code":"private-reason-must-not-be-projected", "workspace_bound":true, "source_ref_external_allowed":false,
        "reviewed_output_sha256":null, "observe_mode":false, "deadline_budget_ms":100,
        "origin_authentication":"f".repeat(64), "execution_intent_digest":"1".repeat(64)
    })).unwrap()
}
fn wire(receipt: &NativeHookDecisionReceiptV1) -> Map<String, Value> {
    serde_json::to_value(receipt)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn receipt_notifications_do_not_collect_when_only_native_policy_facts_are_enabled() {
    let _fixture = global_loss_fixture();
    let observer = Arc::new(Notifications::with_sources(true, false));
    let receipt = receipt(42);
    let home = PathBuf::from(format!(
        "/synthetic-cigar-notification-{}",
        crate::unique_nanos::unique_nanos()
    ));
    assert!(register(home.clone(), &observer));
    native_origin(
        &home,
        Some("/workspace"),
        &receipt,
        &json!({"action":{
            "schema":"guard-pre-tool-action.v1","version":1,"harness":"codex","event":"PreToolUse",
            "action_type":"command","operation":"execute","bounded":true,"sensitive_target":false
        }}),
    );
    assert!(observer.actions.get(&receipt.decision_id).is_ok());
    observer.persisted(&wire(&receipt));
    assert!(observer.drain().unwrap().facts.is_empty());
    assert!(observer.inbox.lock().unwrap().origins.is_empty());
}

#[test]
fn only_persisted_matching_native_origins_become_small_data_only_facts() {
    let _fixture = global_loss_fixture();
    let observer = Notifications::default();
    let receipt = receipt(1);
    let mut mapping = wire(&receipt);
    observer.persisted(&mapping);
    assert!(observer.drain().unwrap().facts.is_empty());
    observer.native_origin("/workspace/project", &receipt);
    assert!(
        observer.drain().unwrap().facts.is_empty(),
        "origin alone is not persisted evidence"
    );
    mapping.insert("origin_authentication".into(), json!("a".repeat(64)));
    observer.persisted(&mapping);
    assert!(observer.drain().unwrap().facts.is_empty());
    mapping = wire(&receipt);
    mapping.insert(
        "raw_command".into(),
        json!("private-command-must-not-be-projected"),
    );
    mapping.insert("harness".into(), json!("forged harness"));
    observer.persisted(&mapping);
    let batch = observer.drain().unwrap();
    assert_eq!(batch.facts.len(), 1);
    let document = batch.facts[0].document();
    assert!(document.text.contains("in codex"));
    assert!(document.text.contains(
        "Recorded policy action: review; observed policy action: not recorded; observe mode: false"
    ));
    assert!(document
        .text
        .contains("not execution confirmation or an approval grant"));
    for private in [
        "private-command",
        "private-reason",
        "forged harness",
        "/workspace/project",
        &"f".repeat(64),
        &"1".repeat(64),
    ] {
        assert!(
            !document.text.contains(private),
            "unexpected projection: {private}"
        );
    }
    observer.persisted(&mapping);
    assert!(
        observer.drain().unwrap().facts.is_empty(),
        "a persisted replay has no new origin"
    );
}

#[test]
fn bounded_origin_and_ready_queues_report_loss_and_keep_the_newest_facts() {
    let _fixture = global_loss_fixture();
    let observer = Notifications::default();
    for index in 1..=ORIGINS + 3 {
        observer.native_origin("/workspace", &receipt(index));
    }
    assert_eq!(observer.inbox.lock().unwrap().origins.len(), ORIGINS);
    observer.persisted(&wire(&receipt(1)));
    let dropped = observer.drain().unwrap();
    assert!(dropped.facts.is_empty());
    assert!(dropped.dropped >= 3);
    for index in 4..=ORIGINS + 3 {
        observer.persisted(&wire(&receipt(index)));
    }
    let batch = observer.drain().unwrap();
    assert_eq!(batch.facts.len(), READY);
    assert!(batch.dropped >= (ORIGINS - READY) as u64);
    assert_eq!(
        batch.facts.last().unwrap().decision_id,
        format!("{:064x}", ORIGINS + 3)
    );
    assert!(observer.inbox.lock().unwrap().order.is_empty());
}

#[test]
fn observed_policy_actions_remain_distinct_and_free_form_actions_are_excluded() {
    let _fixture = global_loss_fixture();
    let observer = Notifications::default();
    let mut receipt = receipt(9);
    receipt.decision = "allow".into();
    receipt.policy_action = None;
    receipt.observed_policy_action = Some("block".into());
    receipt.observe_mode = true;
    observer.native_origin("/workspace", &receipt);
    observer.persisted(&wire(&receipt));
    let text = observer.drain().unwrap().facts[0].document().text;
    assert!(text.contains("decision 'allow'"));
    assert!(text.contains(
        "Recorded policy action: not recorded; observed policy action: block; observe mode: true"
    ));
    receipt.policy_action = Some("private free-form action".into());
    observer.native_origin("/workspace", &receipt);
    assert!(observer.inbox.lock().unwrap().origins.is_empty());
}

#[test]
fn pending_receipts_invalidate_only_matching_workspace_and_harness_reads() {
    let _fixture = global_loss_fixture();
    let observer = Notifications::default();
    let receipt = receipt(10);
    let epoch = observer.epoch();
    observer.native_origin("/workspace/first", &receipt);
    observer.persisted(&wire(&receipt));
    assert!(observer
        .current(epoch, Some((Path::new("/workspace/second"), "dashboard")))
        .is_ok());
    assert!(observer
        .current(epoch, Some((Path::new("/workspace/first"), "claude-code")))
        .is_ok());
    assert!(matches!(
        observer.current(epoch, Some((Path::new("/workspace/first"), "codex"))),
        Err(RuntimeError::ContextStale)
    ));
    assert!(matches!(
        observer.current(epoch, Some((Path::new("/workspace/first"), "dashboard"))),
        Err(RuntimeError::ContextStale)
    ));
    assert!(matches!(
        observer.current(epoch, None),
        Err(RuntimeError::ContextStale)
    ));
    let drained = observer.drain().unwrap();
    assert!(observer
        .current(
            drained.epoch,
            Some((Path::new("/workspace/first"), "dashboard"))
        )
        .is_ok());
}

#[test]
fn contention_is_nonblocking_and_invalidates_the_retained_epoch() {
    let _fixture = global_loss_fixture();
    let observer = Notifications::default();
    let epoch = observer.epoch();
    let guard = observer.inbox.lock().unwrap();
    let started = Instant::now();
    observer.native_origin("/workspace", &receipt(2));
    observer.persisted(&wire(&receipt(2)));
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(observer.epoch() != epoch);
    assert!(matches!(observer.drain(), Err(RuntimeError::Busy)));
    drop(guard);
    assert!(observer.drain().unwrap().dropped >= 2);
    let epoch = observer.epoch();
    missed_origin();
    assert!(observer.epoch() != epoch);
    assert!(matches!(
        observer.current(
            epoch,
            Some((Path::new("/unrelated/workspace"), "claude-code"))
        ),
        Err(RuntimeError::ContextStale)
    ));
    assert!(observer.drain().unwrap().dropped >= 1);
}

#[test]
fn close_restart_and_malformed_origin_never_restore_a_prior_delivery() {
    let _fixture = global_loss_fixture();
    let observer = Notifications::default();
    let mut receipt = receipt(3);
    for path in ["relative", "/workspace/../outside"] {
        observer.native_origin(path, &receipt);
    }
    receipt.origin_authentication = None;
    observer.native_origin("/workspace", &receipt);
    assert!(observer.inbox.lock().unwrap().origins.is_empty());
    receipt.origin_authentication = Some("f".repeat(64));
    observer.native_origin("/workspace", &receipt);
    observer.close();
    observer.persisted(&wire(&receipt));
    assert!(matches!(observer.drain(), Err(RuntimeError::Cancelled)));
    let replacement = Notifications::default();
    replacement.persisted(&wire(&receipt));
    assert!(replacement.drain().unwrap().facts.is_empty());
}
