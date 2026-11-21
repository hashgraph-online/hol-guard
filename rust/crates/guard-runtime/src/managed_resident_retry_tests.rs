use super::super::containment::{is_retryable_live_request_error, is_stale_process_identity_error};

#[test]
fn stale_process_identity_errors_are_platform_scoped() {
    let stale_unavailable =
        is_stale_process_identity_error("native_resident_process_identity_unavailable");
    let stale_mismatch =
        is_stale_process_identity_error("native_resident_process_identity_mismatch");
    assert!(stale_unavailable);
    assert!(stale_mismatch);
    assert!(!is_stale_process_identity_error(
        "native_resident_state_mac_invalid"
    ));
    assert!(!is_stale_process_identity_error(
        "native_client_auth_rejected"
    ));
}

#[test]
fn stale_transport_retry_allowlist_preserves_auth_and_integrity_failures() {
    let retryable_codes = [
        "native_client_connect_failed",
        "native_client_auth_timeout_failed",
        "native_resident_process_identity_unavailable",
        "native_resident_process_identity_mismatch",
    ];
    for code in retryable_codes {
        assert!(is_retryable_live_request_error(
            &crate::resident_client::ResidentClientError {
                code: code.to_owned(),
                retryable_teardown: false,
            }
        ));
    }

    let terminal_codes = [
        "native_client_frame_read_failed",
        "native_client_frame_write_failed",
        "native_client_auth_rejected",
        "native_client_peer_identity_mismatch",
        "native_client_response_binding_failed",
        "native_client_response_digest_mismatch",
    ];
    for retryable_teardown in [false, true] {
        for code in terminal_codes {
            assert!(!is_retryable_live_request_error(
                &crate::resident_client::ResidentClientError {
                    code: code.to_owned(),
                    retryable_teardown,
                }
            ));
        }
    }
    assert!(is_retryable_live_request_error(
        &crate::resident_client::ResidentClientError {
            code: "native_client_auth_nonce_failed".to_owned(),
            retryable_teardown: true,
        }
    ));
    assert!(!is_retryable_live_request_error(
        &crate::resident_client::ResidentClientError {
            code: "native_client_auth_nonce_failed".to_owned(),
            retryable_teardown: false,
        }
    ));
}
