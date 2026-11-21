//! Scope availability is backed by native state, not caller-supplied flags.

use crate::policy_store::PolicySnapshotStore;
use guard_contracts::ApprovalScopeItemV1;
use rusqlite::Connection;

#[cfg(target_os = "macos")]
pub(crate) fn owner_verified(
    item: &ApprovalScopeItemV1,
    store: &PolicySnapshotStore,
    connection: Option<&Connection>,
) -> bool {
    use serde_json::Value;
    let descriptor = item
        .action_envelope_json
        .as_ref()
        .and_then(|value| value.get("native_bash"));
    if !crate::native_bash_review_descriptor::eligible(
        item.artifact_type.as_ref().and_then(Value::as_str),
        item.artifact_id.as_ref().and_then(Value::as_str),
        item.artifact_hash.as_ref().and_then(Value::as_str),
        item.harness.as_ref().and_then(Value::as_str),
        item.raw_command_text.as_ref().and_then(Value::as_str),
        item.workspace_target.as_deref(),
        descriptor,
    ) {
        return false;
    }
    let (Some(request_id), Some(harness), Some(command), Some(descriptor)) = (
        item.request_id.as_ref().and_then(Value::as_str),
        item.harness.as_ref().and_then(Value::as_str),
        item.raw_command_text.as_ref().and_then(Value::as_str),
        descriptor,
    ) else {
        return false;
    };
    let Ok(descriptor) = serde_json::from_value(descriptor.clone()) else {
        return false;
    };
    let verify = |connection: &Connection| {
        crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal::descriptor_is_backed(
            connection, store, request_id, harness, command, &descriptor,
        ).unwrap_or(false)
    };
    if let Some(connection) = connection {
        return verify(connection);
    }
    let Ok(connection) = Connection::open_with_flags(
        store.approval_database_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) else {
        return false;
    };
    if connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .is_err()
    {
        return false;
    }
    verify(&connection)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn owner_verified(
    _: &ApprovalScopeItemV1,
    _: &PolicySnapshotStore,
    _: Option<&Connection>,
) -> bool {
    false
}
