use super::{
    workspace::{candidate, data},
    Fixture,
};
use guard_command::hook_evidence_writer::EvidenceStoreApi;
use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::{json, Value};
use std::path::Path;

struct NoBarrier;
impl crate::hook_evidence_store::PolicyBarrierApi for NoBarrier {
    fn notify_policy_mutation(&self, _: &Path) {
        panic!("receipt admission cannot move policy authority");
    }
}

fn evaluate(fixture: &Fixture, workspace: &Path) -> GuardHookEdgeResultV2 {
    let snapshot = crate::policy_store::tests::signed_snapshot(1, &[29_u8; 32], &fixture.home);
    fixture
        .store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1", "snapshot":snapshot}))
        .unwrap();
    let envelope: GuardHookEnvelopeV2 = serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "request_id":"native-receipt-assistance", "harness":"codex",
        "event":"PreToolUse", "raw_payload":{"tool_name":"exec_command", "tool_input":{"cmd":"printf private-command-must-not-enter-cigar"}},
        "deadline_budget_ms":100, "policy_generation":1, "policy_snapshot":snapshot,
        "source":{"cwd":workspace,"home_dir":workspace,"guard_home":fixture.home,"source_ref_external_allowed":false},
        "recording_only":false
    })).unwrap();
    serde_json::from_slice(
        &crate::edge::evaluate_envelope_with_store(envelope, &fixture.store).unwrap(),
    )
    .unwrap()
}

fn create_receipt_database(home: &Path) {
    let vectors: Value = serde_json::from_str(include_str!(
        "../testdata/guard_store/native_receipt_vectors.json"
    ))
    .unwrap();
    let connection = rusqlite::Connection::open(home.join("guard.db")).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    connection.execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')").unwrap();
}

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_native_evidence_admission_invalidates_context_without_exporting_private_input() {
    let fixture = Fixture::new();
    candidate(&fixture);
    let temporary = tempfile::tempdir().unwrap();
    let workspace = temporary.path().canonicalize().unwrap();
    let granted = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"grant", "workspace":workspace, "app":"dashboard", "sources":[]}),
    ));
    let id = &granted["scope_id"];
    let foreign = temporary.path().join("another-workspace");
    std::fs::create_dir(&foreign).unwrap();
    let foreign = foreign.canonicalize().unwrap();
    let other = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"grant", "workspace":foreign, "app":"dashboard", "sources":[]}),
    ));
    let compile = || {
        fixture.ask_input("workspace", json!({"action":"compile", "scope_id":id, "query":"Guard recorded decision native receipt"}))
    };
    let initial = data(compile());
    let snapshot = &initial["brief"]["snapshot_id"];
    let explain = || {
        fixture.ask_input(
            "workspace",
            json!({"action":"explain", "scope_id":id, "snapshot_id":snapshot}),
        )
    };
    let evaluated = evaluate(&fixture, &workspace);
    crate::policy_store::native_review_origin::verify(&fixture.store, &evaluated.receipt).unwrap();
    assert!(evaluated.receipt.origin_authentication.is_some());
    data(explain());
    let mapping = serde_json::to_value(&evaluated.receipt)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let writer = crate::hook_evidence_store::NativeEvidenceStore::new(
        fixture.home.clone(),
        "guard",
        Box::new(NoBarrier),
    );
    assert!(
        writer.record_native_decision_receipt(&mapping).is_err(),
        "an absent database must not notify"
    );
    data(explain());
    create_receipt_database(&fixture.home);
    assert!(writer.record_native_decision_receipt(&mapping).unwrap());
    assert_eq!(explain()["code"], "native_context_assistance_context_stale");
    let unrelated = data(fixture.ask_input("workspace", json!({"action":"compile", "scope_id":other["scope_id"], "query":"Guard recorded decision native receipt"})));
    assert!(
        !unrelated["brief"]["rendered"]
            .as_str()
            .unwrap()
            .contains(&evaluated.receipt.decision_id),
        "native receipt facts cannot cross workspace grants"
    );
    let current = data(compile());
    let brief = &current["brief"];
    let rendered = brief["rendered"].as_str().unwrap();
    assert!(rendered.contains(&evaluated.receipt.decision_id), "{brief}");
    assert!(rendered.contains("not execution confirmation or an approval grant"));
    assert!(brief["citations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|citation| citation["source"] == "guard:receipts"));
    for private in [
        "private-command-must-not-enter-cigar",
        fixture.home.to_str().unwrap(),
        workspace.to_str().unwrap(),
        evaluated.receipt.origin_authentication.as_deref().unwrap(),
    ] {
        assert!(!rendered.contains(private), "unexpected private field");
    }
    let listed = data(fixture.ask_input("workspace", json!({"action":"list"})));
    let affected = listed["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scope| scope["scope_id"] == *id)
        .unwrap();
    assert_eq!(affected["receipt_window"]["retained"], 1);
    assert!(
        writer.record_native_decision_receipt(&mapping).unwrap(),
        "duplicate evidence stays successfully acknowledged"
    );
    let current_id = &brief["snapshot_id"];
    data(fixture.ask_input(
        "workspace",
        json!({"action":"explain", "scope_id":id, "snapshot_id":current_id}),
    ));
    // Exercise the producer's finite nonblocking delivery failure against
    // an actual SDK source, not just the mailbox's counter.
    crate::context_assistance_notifications::missed_origin();
    assert_eq!(
        fixture.ask_input(
            "workspace",
            json!({"action":"explain", "scope_id":id, "snapshot_id":current_id})
        )["code"],
        "native_context_assistance_context_stale"
    );
    let after_loss = data(compile());
    assert!(!after_loss["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains(&evaluated.receipt.decision_id));
    let after_loss = data(fixture.ask_input("workspace", json!({"action":"list"})));
    let affected = after_loss["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scope| scope["scope_id"] == *id)
        .unwrap();
    assert_eq!(affected["receipt_window"]["retained"], 0);
    assert_ne!(affected["receipt_window"]["dropped"], "0");
    fixture.ask("stop");
    assert!(
        writer.record_native_decision_receipt(&mapping).unwrap(),
        "off cannot alter evidence admission"
    );
    assert_eq!(compile()["code"], "native_context_assistance_disabled");
    println!(
        "GUARD_CIGAR_RECEIPT_VERIFICATION={}",
        json!({"schema":"guard-cigar-receipt-verification.v1", "status":"passed", "qualification":"local-development-darwin-arm64-only", "brief":brief,
        "checks":["real_native_hook_origin", "failed_store_no_notification", "post_commit_notification", "stale_snapshot_refusal", "actual_sdk_receipt_citation", "private_input_exclusion", "exact_workspace_isolation", "loss_invalidates_actual_sdk_source", "duplicate_ack_preserved", "opt_out_evidence_independence"]})
    );
}
