use super::*;
use serde_json::{json, Value};

pub(super) fn row(address: &str) -> Value {
    json!({"kind":"admin#directory#user", "id":address, "primaryEmail":address,
        "customerId":"C012345", "suspended":false, "etag":"synthetic-etag"})
}
pub(super) fn grant() -> GoogleDirectoryCredential {
    GoogleDirectoryCredential {
        credential: crate::oauth::directory_test_credential(),
        customer_id: "C012345".into(),
        namespace_key: Zeroizing::new([7; 32]),
    }
}
pub(super) fn input() -> InspectedGoogleWorkerInput {
    crate::oauth::worker_input_tests::credential("subject-one")
        .prepare_command(crate::oauth::worker_input_tests::command(
            "sender@work.example",
            "ordinary text",
        ))
        .unwrap()
        .inspect_outbound()
        .unwrap()
}
pub(super) fn bytes(row: &Value) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(row).unwrap())
}

fn addressed_input(to: &str) -> InspectedGoogleWorkerInput {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let mime = format!("From: sender@work.example\r\nTo: {to}\r\nSubject: Synthetic\r\nContent-Type: text/plain\r\n\r\nbody");
    let raw = Base64UrlUnpadded::encode_string(mime.as_bytes());
    let command = format!("gws gmail users messages send --params '{{\"userId\":\"me\"}}' --json '{{\"raw\":\"{raw}\"}}'");
    crate::oauth::worker_input_tests::credential("subject-one")
        .prepare_command(command)
        .unwrap()
        .inspect_outbound()
        .unwrap()
}

#[test]
fn duplicate_principal_aliases_and_oversized_pilot_audiences_refuse() {
    let result = grant().resolve_with(
        addressed_input("recipient@work.example, alias@work.example"),
        |_, address| {
            let mut value = row(address);
            if address != "sender@work.example" {
                value = row("recipient@work.example");
                value["aliases"] = json!(["alias@work.example"]);
            }
            Ok(bytes(&value))
        },
    );
    assert_eq!(result.err(), Some(DirectoryError::Unresolved));
    let addresses = (0..9)
        .map(|n| format!("user{n}@work.example"))
        .collect::<Vec<_>>()
        .join(", ");
    let result = grant().resolve_with(addressed_input(&addresses), |_, _| {
        panic!("oversized pilot must refuse before provider lookup")
    });
    assert_eq!(result.err(), Some(DirectoryError::Unresolved));
}

#[test]
fn provider_user_and_exact_alias_resolve_to_one_private_principal() {
    let mut row = row("primary@work.example");
    row["aliases"] = json!(["alias@work.example"]);
    assert!(User::from_bytes(&bytes(&row), "alias@work.example", "C012345").is_ok());
    assert!(User::from_bytes(&bytes(&row), "other@work.example", "C012345").is_err());
    let resolved = grant()
        .resolve_with(input(), |_, address| Ok(bytes(&super::tests::row(address))))
        .unwrap();
    assert!(resolved.is_current());
    assert_eq!(resolved.recipients().len(), 1);
    assert_eq!(resolved.recipients()[0].address(), "recipient@work.example");
    assert_eq!(resolved.recipients()[0].principal_binding().len(), 64);
    assert_eq!(resolved.resolution_binding().len(), 64);
}

#[test]
fn malformed_groups_suspended_archived_foreign_customer_and_ambiguous_aliases_refuse() {
    for (field, value) in [
        ("kind", json!("admin#directory#group")),
        ("suspended", json!(true)),
        ("archived", json!(true)),
        (
            "aliases",
            json!(["alias@work.example", "alias@work.example"]),
        ),
        ("aliases", json!(["Display <alias@work.example>"])),
        ("etag", json!("")),
        ("customerId", json!("FOREIGN")),
        ("unknown", json!(true)),
    ] {
        let mut value_row = row("recipient@work.example");
        value_row[field] = value;
        assert!(User::from_bytes(&bytes(&value_row), "recipient@work.example", "C012345").is_err());
    }
    let raw = br#"{"kind":"admin#directory#user","id":"one","id":"two","primaryEmail":"recipient@work.example","customerId":"C012345","suspended":false,"etag":"one"}"#;
    assert!(User::from_bytes(raw, "recipient@work.example", "C012345").is_err());
    assert!(User::from_bytes(
        &vec![b' '; 64 * 1024 + 1],
        "recipient@work.example",
        "C012345"
    )
    .is_err());
}

#[test]
fn provider_failure_and_expired_resolution_do_not_release_input() {
    assert_eq!(
        grant()
            .resolve_with(input(), |_, _| Err(DirectoryError::Unavailable))
            .err(),
        Some(DirectoryError::Unavailable)
    );
    let mut resolved = grant()
        .resolve_with(input(), |_, address| Ok(bytes(&row(address))))
        .unwrap();
    resolved.deadline = Instant::now();
    assert!(!resolved.is_current());
}

#[test]
fn prepared_business_facts_derive_from_private_provider_evidence_and_frozen_wire() {
    let resolved = grant()
        .resolve_with(input(), |_, address| Ok(bytes(&row(address))))
        .unwrap();
    let request = resolved.prepare_business_request().unwrap();
    let prepared = request.prepared_input();
    assert!(request.is_current());
    assert_eq!(
        prepared.facts().operation,
        guard_contracts::BusinessOperationV1::MailSend
    );
    assert_eq!(prepared.facts().volume.recipient_count, 1);
    assert_eq!(
        prepared.facts().volume.byte_count,
        prepared.primary_bytes().len() as u64
    );
    assert_eq!(
        prepared.facts().content.inspected_bytes,
        prepared.primary_bytes().len() as u64
    );
    assert_eq!(
        prepared.facts().target.revision_binding,
        request.resolution_binding()
    );
    assert!(prepared
        .facts()
        .content
        .sensitivity_labels
        .contains(&guard_contracts::BusinessSensitivityV1::Confidential));
    assert!(!prepared
        .facts()
        .content
        .sensitivity_labels
        .contains(&guard_contracts::BusinessSensitivityV1::Public));
    prepared.facts().validate().unwrap();
}
