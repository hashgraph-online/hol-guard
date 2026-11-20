use std::collections::BTreeMap;

use super::*;

fn refusal(status: u16, body: &str) -> FetchError {
    http_failure(&SyncHttpFailure {
        status,
        headers: BTreeMap::new(),
        body: body.as_bytes().to_vec(),
    })
}

#[test]
fn outages_are_retryable_and_other_transport_failures_are_not() {
    for text in [
        format!("io: {}", std::io::ErrorKind::ConnectionRefused),
        format!("io: {}", std::io::ErrorKind::ConnectionReset),
        format!("io: {}", std::io::ErrorKind::TimedOut),
        "io: ConnectionRefused".to_owned(),
        "host not found".to_owned(),
        "timeout: 20s".to_owned(),
    ] {
        let text = text.as_str();
        assert!(
            guard_command::guard_sync_transport::is_network_outage_reason(text),
            "{text}"
        );
        assert_eq!(
            transport_failure(&EvalError::Internal(text.to_owned())),
            SyncError::NotAvailable {
                message: GUARD_CLOUD_UNREACHABLE_MESSAGE.to_owned(),
                retryable: true,
            }
        );
    }
    for text in [
        "tls",
        "io: permission denied",
        "io: PermissionDenied",
        "transport",
        "response too large",
    ] {
        assert!(
            !guard_command::guard_sync_transport::is_network_outage_reason(text),
            "{text}"
        );
    }
    assert_eq!(
        transport_failure(&EvalError::Internal("tls".to_owned())),
        SyncError::Failed("Guard sync failed: tls".to_owned())
    );
    assert_eq!(
        transport_failure(&EvalError::Internal("  ".to_owned())),
        SyncError::Failed(
            "Guard sync failed because the remote endpoint could not be reached.".to_owned()
        )
    );
}

#[test]
fn a_plan_that_turned_sync_off_is_not_available() {
    let FetchError::Sync(SyncError::NotAvailable { message, retryable }) = refusal(
        403,
        r#"{"error":"Sync is off for this plan.","syncEnabled":false}"#,
    ) else {
        panic!("a disabled plan is not available");
    };
    assert_eq!(message, "Sync is off for this plan.");
    assert!(!retryable);
}

#[test]
fn an_unavailable_cloud_is_retryable() {
    assert!(matches!(
        refusal(503, ""),
        FetchError::Sync(SyncError::NotAvailable {
            retryable: true,
            ..
        })
    ));
}

#[test]
fn a_refused_token_can_be_refreshed() {
    assert!(matches!(refusal(401, ""), FetchError::Unauthorized(_)));
}

#[test]
fn a_server_error_fails_the_sync() {
    assert!(matches!(
        refusal(500, ""),
        FetchError::Sync(SyncError::Failed(_))
    ));
}

#[test]
fn an_unauthorized_fetch_fails_once_it_reaches_the_caller() {
    assert_eq!(
        SyncError::from(FetchError::Unauthorized("refused".to_owned())),
        SyncError::Failed("refused".to_owned())
    );
}

#[test]
fn a_refresh_that_cannot_reach_guard_cloud_is_a_retryable_outage() {
    let unreachable = EvalError::Internal(format!(
        "{} io: {}",
        gst::OAUTH_REFRESH_UNREACHABLE,
        std::io::ErrorKind::ConnectionRefused
    ));
    assert_eq!(
        auth_error(unreachable),
        SyncError::NotAvailable {
            message: GUARD_CLOUD_UNREACHABLE_MESSAGE.to_owned(),
            retryable: true,
        }
    );
    assert_eq!(
        auth_error(EvalError::Validation("reconnect".to_owned())),
        SyncError::AuthExpired("reconnect".to_owned())
    );
    assert_eq!(
        auth_error(EvalError::Internal("tls: bad certificate".to_owned())),
        SyncError::Failed("tls: bad certificate".to_owned())
    );
}
