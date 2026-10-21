//! Verification-key kinds of the `PolicyBundleAuthority` op.

use serde_json::{json, Value};

use crate::policy_bundle_keys::{
    key_is_current, key_is_trusted, keys_to_value, load_keys, resolve_authorized, Key,
};
use crate::policy_bundle_keys_ctx::{migrate_legacy, persistable, sync_keys, verification_context};
use crate::policy_bundle_op::{
    field, flag, keys_field, number_field, object_document, optional_text, text_field, Fail,
    Handled,
};
use crate::policy_bundle_py::Obj;

fn one_key(input: &Obj, name: &str) -> Result<Key, Fail> {
    Key::from_wire(field(input, name)?).ok_or(Fail::Invalid)
}

fn load(input: &Obj) -> Handled {
    let raw = field(input, "raw")?;
    let loaded = load_keys(raw, flag(input, "require_contract")?);
    let keys = if flag(input, "safe")? {
        loaded.unwrap_or_default()
    } else {
        loaded?
    };
    Ok(json!({ "keys": keys_to_value(&keys) }))
}

fn authorized(input: &Obj) -> Handled {
    let (trusted, anchored) = (
        keys_field(input, "trusted_keys")?,
        keys_field(input, "anchored_keys")?,
    );
    let key = resolve_authorized(
        text_field(input, "key_id")?,
        &trusted,
        &anchored,
        optional_text(input, "expected_workspace_id")?,
        number_field(input, "now")?,
    )?;
    Ok(json!({ "key": key.to_value() }))
}

/// Inputs shared by the context-assembly kinds.
pub(crate) struct ContextInput<'a> {
    pub stored_keyring: &'a Value,
    pub sync_keys: Vec<Key>,
    pub managed_configured: bool,
    pub managed_keys: Vec<Key>,
    pub provenance_present: bool,
    pub expected_workspace: Option<&'a str>,
}

pub(crate) fn context_input(input: &Obj) -> Result<ContextInput<'_>, Fail> {
    Ok(ContextInput {
        stored_keyring: field(input, "stored_keyring")?,
        sync_keys: sync_keys(field(input, "sync_keys_raw")?),
        managed_configured: flag(input, "managed_configured")?,
        managed_keys: keys_field(input, "managed_keys")?,
        provenance_present: flag(input, "provenance_present")?,
        expected_workspace: optional_text(input, "expected_workspace_id")?,
    })
}

fn context(input: &Obj) -> Handled {
    let given = context_input(input)?;
    let built = verification_context(
        given.stored_keyring,
        &given.sync_keys,
        given.managed_configured,
        &given.managed_keys,
        given.provenance_present,
        given.expected_workspace,
    );
    Ok(json!({
        "trusted_keys": keys_to_value(&built.trusted),
        "anchored_keys": keys_to_value(&built.anchored),
        "managed_configured": built.managed_configured,
    }))
}

fn migrate(input: &Obj) -> Handled {
    let migrated = migrate_legacy(
        field(input, "stored_keyring")?,
        &sync_keys(field(input, "sync_keys_raw")?),
        optional_text(input, "expected_workspace_id")?,
    );
    Ok(json!({ "keys": keys_to_value(&migrated) }))
}

fn persist(input: &Obj) -> Handled {
    let bundle = object_document(input, "bundle_chunks")?;
    let kept = persistable(&keys_field(input, "anchored_keys")?, &Value::Object(bundle));
    Ok(json!({ "keys": keys_to_value(&kept) }))
}

pub(crate) fn handle(kind: &str, input: &Obj) -> Option<Handled> {
    Some(match kind {
        "load_keys" => load(input),
        "key_is_current" => one_key(input, "key").and_then(|key| {
            let current = key_is_current(
                &key,
                number_field(input, "now")?,
                flag(input, "require_active")?,
            );
            Ok(json!({ "value": current }))
        }),
        "key_is_trusted" => one_key(input, "key").and_then(|key| {
            let trusted = key_is_trusted(&key, &keys_field(input, "anchored_keys")?);
            Ok(json!({ "value": trusted }))
        }),
        "resolve_authorized" => authorized(input),
        "verification_context" => context(input),
        "migrate_legacy" => migrate(input),
        "persistable" => persist(input),
        "validate_synced" => crate::policy_bundle_op_synced::synced(input),
        _ => return None,
    })
}
