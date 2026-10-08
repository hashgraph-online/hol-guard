use super::*;
use std::sync::Arc;
use std::thread;

mod transition_tests {
    include!("approval_replay_memory_transition_tests.rs");
}

fn binding(expires_at_ms: u64) -> ApprovalReplayBinding {
    ApprovalReplayBinding {
        request_id_digest: "1".repeat(64),
        request_digest: "2".repeat(64),
        action_digest: "3".repeat(64),
        policy_generation: 1,
        policy_digest: "4".repeat(64),
        rule_digest: "5".repeat(64),
        runtime_identity: "6".repeat(64),
        runtime_binary_identity: "6".repeat(64),
        harness: "test".to_owned(),
        workspace_binding: Some("7".repeat(64)),
        device_binding: Some("8".repeat(64)),
        installation_binding: Some("9".repeat(64)),
        publisher_binding: None,
        artifact_binding: None,
        scope_contract_version: "guard-native-scope.v1".to_owned(),
        scope_contract_digest: "8".repeat(64),
        scope_binding: Some("a".repeat(64)),
        expires_at_ms,
    }
}

#[test]
fn restart_epoch_rejects_old_artifact_state() {
    let first = ApprovalReplayMemory::new().unwrap();
    let now = 10;
    let nonce = "a".repeat(64);
    let epoch = first.epoch().to_owned();
    let replay_binding = binding(100);
    first
        .register_pending(&nonce, replay_binding.clone(), now)
        .unwrap();
    let second = ApprovalReplayMemory::new().unwrap();
    assert_ne!(epoch, second.epoch());
    assert_eq!(
        second
            .claim(&epoch, &nonce, &replay_binding, now)
            .unwrap_err(),
        "native_approval_receipt_not_claimed"
    );
}

#[test]
fn expiry_and_double_consume_are_atomic() {
    let memory = Arc::new(ApprovalReplayMemory::new().unwrap());
    let nonce = "b".repeat(64);
    let epoch = memory.epoch().to_owned();
    let expired_binding = binding(20);
    memory
        .register_pending(&nonce, expired_binding.clone(), 10)
        .unwrap();
    assert_eq!(
        memory
            .claim(&epoch, &nonce, &expired_binding, 20)
            .unwrap_err(),
        "native_approval_receipt_expired"
    );

    let nonce = "c".repeat(64);
    let replay_binding = binding(100);
    memory
        .register_pending(&nonce, replay_binding.clone(), 10)
        .unwrap();
    memory.claim(&epoch, &nonce, &replay_binding, 10).unwrap();
    let first = Arc::clone(&memory);
    let second = Arc::clone(&memory);
    let first_epoch = epoch.clone();
    let second_epoch = epoch.clone();
    let first_nonce = nonce.clone();
    let second_nonce = nonce.clone();
    let first_binding = replay_binding.clone();
    let second_binding = replay_binding;
    let first_thread =
        thread::spawn(move || first.consume(&first_epoch, &first_nonce, &first_binding, 10));
    let second_thread =
        thread::spawn(move || second.consume(&second_epoch, &second_nonce, &second_binding, 10));
    let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                matches!(outcome, Err(error) if error == "native_approval_receipt_consumed")
            })
            .count(),
        1
    );
}

#[test]
fn capacity_is_bounded_without_eviction() {
    let memory = ApprovalReplayMemory::new().unwrap();
    let replay_binding = binding(100);
    for index in 0..NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES {
        memory
            .register_pending(&format!("{index:064x}"), replay_binding.clone(), 10)
            .unwrap();
    }
    assert_eq!(memory.len(), NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES);
    assert_eq!(
        memory
            .register_pending(&"f".repeat(64), replay_binding, 10)
            .unwrap_err(),
        "native_approval_replay_full"
    );
}

#[test]
fn full_binding_mutation_is_rejected_before_state_transition() {
    let memory = ApprovalReplayMemory::new().unwrap();
    let nonce = "d".repeat(64);
    let epoch = memory.epoch().to_owned();
    let original = binding(100);
    memory
        .register_pending(&nonce, original.clone(), 10)
        .unwrap();
    let mut altered = original.clone();
    altered.scope_binding = Some("b".repeat(64));
    assert_eq!(
        memory.claim(&epoch, &nonce, &altered, 10).unwrap_err(),
        "native_approval_binding_mismatch"
    );
    memory.claim(&epoch, &nonce, &original, 10).unwrap();
}
