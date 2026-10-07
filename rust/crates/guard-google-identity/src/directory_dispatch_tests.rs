use super::*;
use crate::directory::tests::{bytes, grant, input, row};
use crate::dispatch::Acknowledgement;
use std::time::Instant;
use zeroize::Zeroizing;

fn prepared() -> PreparedGoogleBusinessRequest {
    grant()
        .resolve_with(input(), |_, address| Ok(bytes(&row(address))))
        .unwrap()
        .prepare_business_request()
        .unwrap()
}
fn owned(input: &PreparedGoogleBusinessRequest) -> PreparedBusinessInputV1 {
    PreparedBusinessInputV1::prepare(
        &serde_json::to_vec(input.prepared_input().facts()).unwrap(),
        input.prepared_input().primary_bytes().to_vec(),
        vec![],
    )
    .unwrap()
}

#[test]
fn ownership_boundary_preserves_frozen_json_and_fingerprints_private_response() {
    let input = prepared();
    let frozen = owned(&input);
    let body = frozen.primary_bytes().to_vec();
    let expected = crate::binding(
        &input.resolved.directory.namespace_key,
        b"hol-guard.google-send-acknowledgement.v1\0",
        &[
            input
                .prepared_input()
                .facts()
                .provider
                .account_binding
                .as_deref()
                .unwrap(),
            "synthetic-id",
            "synthetic-thread",
        ],
    );
    let attempt = input
        .dispatch_with(frozen, |_, bytes| {
            assert_eq!(bytes, body);
            Ok(RawSendAttempt::Accepted(Acknowledgement {
                id: Zeroizing::new("synthetic-id".into()),
                thread_id: Zeroizing::new("synthetic-thread".into()),
            }))
        })
        .unwrap();
    assert_eq!(
        attempt,
        GoogleSendAttempt::ApiAccepted {
            message_binding: expected
        }
    );
}

#[test]
fn changed_owned_snapshot_and_expired_resolution_cannot_enter_transport() {
    let input = prepared();
    let mut facts = input.prepared_input().facts().clone();
    facts.provider.account_binding = Some("1".repeat(64));
    let changed = PreparedBusinessInputV1::prepare(
        &serde_json::to_vec(&facts).unwrap(),
        input.prepared_input().primary_bytes().to_vec(),
        vec![],
    )
    .unwrap();
    let never = |_, _: &[u8]| -> Result<RawSendAttempt, GoogleDispatchError> {
        panic!("no effect permitted");
    };
    assert_eq!(
        input.dispatch_with(changed, never),
        Err(GoogleDispatchError::InputChanged)
    );
    let mut input = prepared();
    let frozen = owned(&input);
    input.resolved.deadline = Instant::now();
    assert_eq!(
        input.dispatch_with(frozen, never),
        Err(GoogleDispatchError::Expired)
    );
}
