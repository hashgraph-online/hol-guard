use super::*;
use crate::oauth::worker_input_tests::{command, credential};

fn input(account: &GoogleSendAccount, body: &str) -> GoogleWorkerInput {
    account
        .prepare_command(command("sender@work.example", body))
        .unwrap()
}

#[test]
fn poisoned_owner_refuses_inputs_and_replacement_even_after_local_revoke() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = input(&account, "pending");
    let active = Arc::clone(&account.active);
    assert!(std::thread::spawn(move || {
        let _writer = active.write().unwrap();
        panic!("synthetic lease poisoning");
    })
    .join()
    .is_err());
    assert!(!account.is_current() && !pending.is_current());
    assert_eq!(
        account
            .prepare_command(command("sender@work.example", "new"))
            .err(),
        Some(GoogleWorkerInputError::Expired)
    );
    assert_eq!(
        account.replace(credential("subject-one")),
        Err(GoogleSendAccountError::Unavailable)
    );
    account.revoke();
    assert!(!account.is_current());
}

#[test]
fn reusable_owner_prepares_distinct_owned_inputs_without_exporting_credentials() {
    let account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let first = input(&account, "first");
    let second = input(&account, "second");
    assert_ne!(first.input_binding(), second.input_binding());
    assert_eq!(
        first.identity().account_binding(),
        second.identity().account_binding()
    );
    assert!(first.is_current() && second.is_current() && account.is_current());
}

#[test]
fn revoke_and_drop_invalidate_prepared_inputs_and_prevent_new_inputs() {
    let account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = input(&account, "pending");
    account.revoke();
    assert!(!pending.is_current());
    assert_eq!(
        account
            .prepare_command(command("sender@work.example", "new"))
            .err(),
        Some(GoogleWorkerInputError::Expired)
    );
    let account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = input(&account, "drop");
    drop(account);
    assert!(!pending.is_current());
}

#[test]
fn same_account_replacement_invalidates_old_inputs_and_permits_new_inputs() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let old = input(&account, "old");
    let old_binding = old.input_binding().to_owned();
    let old_inspection = input(&account, "old")
        .inspect_outbound()
        .unwrap()
        .inspection_binding()
        .to_owned();
    account.replace(credential("subject-one")).unwrap();
    assert!(!old.is_current());
    assert_ne!(input(&account, "old").input_binding(), old_binding);
    assert_ne!(
        input(&account, "old")
            .inspect_outbound()
            .unwrap()
            .inspection_binding(),
        old_inspection
    );
    assert!(input(&account, "fresh").is_current());
    account.revoke();
    assert_eq!(
        account.replace(credential("subject-one")),
        Err(GoogleSendAccountError::Unavailable)
    );
}

#[test]
fn changed_tenant_or_verified_mailbox_refuses_replacement() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let old = input(&account, "old");
    let mut changed = credential("subject-one");
    changed.identity.tenant_binding = "d".repeat(64);
    assert_eq!(
        account.replace(changed),
        Err(GoogleSendAccountError::IdentityChanged)
    );
    let mut changed = credential("subject-one");
    changed.identity.sender =
        crate::sender::VerifiedSender::from_claims(Some("other@work.example".into()), Some(true));
    assert_eq!(
        account.replace(changed),
        Err(GoogleSendAccountError::IdentityChanged)
    );
    assert!(old.is_current() && account.is_current());
}

#[test]
fn wrong_account_purpose_and_expired_replacement_never_replace_current_owner() {
    let mut account = GoogleSendAccount::new(credential("subject-one")).unwrap();
    let pending = input(&account, "pending");
    assert_eq!(
        account.replace(credential("subject-two")),
        Err(GoogleSendAccountError::IdentityChanged)
    );
    let mut expired = credential("subject-one");
    expired.expires_monotonic = std::time::Instant::now();
    assert_eq!(
        account.replace(expired),
        Err(GoogleSendAccountError::Unavailable)
    );
    assert_eq!(
        account.replace(crate::oauth::directory_test_credential()),
        Err(GoogleSendAccountError::Unavailable)
    );
    assert!(pending.is_current() && account.is_current());
    assert_eq!(
        GoogleSendAccount::new(crate::oauth::directory_test_credential()).err(),
        Some(GoogleSendAccountError::Unavailable)
    );
}
