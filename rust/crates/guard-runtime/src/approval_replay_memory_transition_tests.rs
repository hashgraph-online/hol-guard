use super::*;

#[test]
fn failed_emit_restores_claim_for_retry() {
    let memory = ApprovalReplayMemory::new().unwrap();
    let nonce = "e".repeat(64);
    let epoch = memory.epoch().to_owned();
    let replay_binding = binding(100);
    memory
        .register_pending(&nonce, replay_binding.clone(), 10)
        .unwrap();
    assert_eq!(
        memory
            .claim_and_emit(&epoch, &nonce, &replay_binding, 10, || {
                Err("native_approval_response_encode_failed".to_owned())
            })
            .unwrap_err(),
        "native_approval_response_encode_failed"
    );
    memory.claim(&epoch, &nonce, &replay_binding, 10).unwrap();
}

#[test]
fn every_transition_prunes_expired_entries() {
    let memory = ApprovalReplayMemory::new().unwrap();
    let expired_nonce = "f".repeat(64);
    let live_nonce = "1".repeat(64);
    let epoch = memory.epoch().to_owned();
    memory
        .register_pending(&expired_nonce, binding(20), 10)
        .unwrap();
    let live_binding = binding(100);
    memory
        .register_pending(&live_nonce, live_binding.clone(), 10)
        .unwrap();
    memory
        .claim(&epoch, &live_nonce, &live_binding, 20)
        .unwrap();
    assert_eq!(memory.len(), 1);
}
