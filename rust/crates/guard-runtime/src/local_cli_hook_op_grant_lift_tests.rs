//! An allowed grant lifts only a review due to non-recognition.

use super::*;

#[test]
fn an_allowed_grant_leaves_a_review_with_its_own_risk_signal() {
    let fixture = Fixture::new("risk-signal");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    for (action, reason) in [
        ("review", "native_network_review"),
        ("review", "shell_local_secret_read"),
        ("require-reapproval", "native_policy_reapproval_required"),
    ] {
        let mut request = fixture.request("npm run build", action, true);
        request.current_reason_code = Some(reason.to_owned());
        assert_eq!(run(&request), Ok(action.to_owned()), "{reason}");
    }
    let blocked = Fixture::new("risk-signal-blocked");
    let identity = blocked.identity();
    blocked.grant(&identity.cli_id, &identity.identity_hash, "blocked");
    let mut request = blocked.request("npm run build", "review", true);
    request.current_reason_code = Some("native_network_review".to_owned());
    assert_eq!(run(&request), Ok("block".to_owned()));
}
