use super::*;

#[test]
fn generation_parser_rejects_zero_and_non_numeric() {
    assert!(parse_generation("0").is_err());
    assert!(parse_generation("not-a-number").is_err());
    assert_eq!(parse_generation("7").unwrap(), 7);
}

#[test]
fn client_deadline_is_bounded() {
    assert_eq!(
        client_timeout(br#"{"deadline_budget_ms":999999}"#),
        Duration::from_secs(9)
    );
    assert_eq!(client_timeout(br#"{}"#), Duration::from_millis(750));
}

#[test]
fn stale_process_identity_errors_are_platform_scoped() {
    let stale_unavailable =
        is_stale_process_identity_error("native_resident_process_identity_unavailable");
    let stale_mismatch =
        is_stale_process_identity_error("native_resident_process_identity_mismatch");
    if cfg!(windows) {
        assert!(stale_unavailable);
        assert!(stale_mismatch);
    } else {
        assert!(!stale_unavailable);
        assert!(!stale_mismatch);
    }
    assert!(!is_stale_process_identity_error(
        "native_resident_state_mac_invalid"
    ));
    assert!(!is_stale_process_identity_error(
        "native_client_auth_rejected"
    ));
}
