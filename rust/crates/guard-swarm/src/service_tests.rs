use super::*;

#[test]
fn control_actions_can_replay_when_receipts_are_full() {
    let registry = Registry {
        receipts: (0..2048)
            .map(|index| (format!("request-{index}"), ("digest".into(), "run".into())))
            .collect(),
        ..Default::default()
    };

    assert!(matches!(
        replay(&registry, "new-message", "digest", false),
        Err("swarm_request_limit")
    ));
    assert!(matches!(
        replay(&registry, "new-stop", "digest", true),
        Ok(None)
    ));
}
