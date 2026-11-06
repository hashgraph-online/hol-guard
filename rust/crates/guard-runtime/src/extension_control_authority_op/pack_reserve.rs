//! The command-pack half of `commit_prepare`: `activation_journal.reserve`,
//! inside the immediate transaction that writes the prepared row.
//!
//! The staged activation is authenticated, checked against the protected
//! state it was staged under (the lifecycle floor and the active security
//! record, which the caller reads from the policy-integrity store) and against
//! the active slot it extends, then reserved for this row behind a link that
//! binds it to the row's revision, snapshot and catalog. The caller retains
//! the legacy baseline and upgrades the schema marker before it asks.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::params;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::pack_finish::{
    lifecycle, marker_version, pack, record_request, verified, ACTIVATION_MISSING, BASELINE_SCHEMA,
    CONFLICT, PACK_SCHEMA_VERSIONS, REVISION_INVALID, SCHEMA_INVALID, SCHEMA_V2,
};
use super::records::{degraded, query_row, row_int, row_str, store_fault, Fault, Res};
use super::{Ctx, STORE_UNAVAILABLE};
use crate::local_store_read::table_exists;

const DRAFT_INVALID: &str = "native_command_pack_draft_invalid";
const RESERVATION_CONFLICT: &str = "native_command_pack_reservation_conflict";
const FLOOR_CONFLICT: &str = "pack_lifecycle_prepared_floor_conflict";

/// A record the staged draft could not authenticate is refused by name, never
/// reported as a tampered authority.
fn draft_fault(fault: Fault) -> Fault {
    match fault {
        Fault::Tampered(reason) => pack(&reason),
        other => other,
    }
}

impl Ctx<'_> {
    /// Reserve the staged activation for the prepared row at `revision`.
    pub(super) fn reserve_pack(
        &self,
        expected: &str,
        revision: i64,
        snapshot_digest: &str,
        catalog_digest: &str,
    ) -> Res<()> {
        let reserve = self
            .request
            .pack_reserve
            .as_ref()
            .ok_or_else(|| pack(DRAFT_INVALID))?;
        if reserve.record_digest != expected {
            return Err(pack(DRAFT_INVALID));
        }
        let key = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&reserve.key_b64)
                .map_err(|_| pack("native_command_pack_key_invalid"))?,
        );
        let key_hex = Zeroizing::new(hex::encode(key.as_slice()));
        // `lifecycle_store.check`: the floor is the one the draft was staged
        // against, or the one it moves to.
        lifecycle(&json!({"kind": "read", "key": key_hex.as_str(), "floor": reserve.floor}))?;
        let floor = reserve.floor.as_deref();
        if floor != Some(reserve.lifecycle_before.as_str())
            && floor != Some(reserve.lifecycle_after.as_str())
        {
            return Err(pack(FLOOR_CONFLICT));
        }
        crate::active_pack_security::evaluate(&json!({
            "operation": "check",
            "key": key_hex.as_str(),
            "record": reserve.security,
            "expected": reserve.security_digest,
        }))
        .map_err(Fault::Pack)?;
        let header = verified(
            &key_hex,
            json!({
                "purpose": "activation",
                "record": reserve.record_json,
                "digest": reserve.record_digest,
                "mac": reserve.record_mac,
            }),
        )
        .map_err(draft_fault)?;
        let admission = lifecycle(&json!({
            "kind": "admission",
            "profile": header.get("authority_profile").cloned().unwrap_or(json!("remote")),
            "issued_at": header["issued_at"],
            "expires_at": header["expires_at"],
            "now": reserve.admitted_at,
        }))?;
        if admission["current"] != json!(true) || header["catalog_digest"] != json!(catalog_digest)
        {
            return Err(pack(DRAFT_INVALID));
        }
        let version = marker_version(self.connection)?;
        if header["schema"] == SCHEMA_V2 && version < PACK_SCHEMA_VERSIONS[1] {
            return Err(pack(SCHEMA_INVALID));
        }
        let previous_digest = self.active_digest(&key_hex)?;
        if previous_digest != reserve.previous_digest
            || header["previous_digest"] != json!(previous_digest)
        {
            return Err(pack(CONFLICT));
        }
        let journal = table_exists(self.connection, "extension_command_pack_pending")
            .map_err(|_| degraded(STORE_UNAVAILABLE))?;
        if !journal {
            return Err(pack(SCHEMA_INVALID));
        }
        if query_row(
            self.connection,
            "select 1 from extension_command_pack_pending where control_revision = ?",
            [revision],
        )?
        .is_some()
        {
            return Err(pack(RESERVATION_CONFLICT));
        }
        // The link is authenticated apart from the data and control records,
        // so copying a draft to another approved transition cannot reuse it.
        let mut payload = json!({
            "control_revision": revision,
            "snapshot_digest": snapshot_digest,
            "catalog_digest": catalog_digest,
            "pack_record_digest": reserve.record_digest,
            "admitted_at": reserve.admitted_at,
            "lifecycle_before": reserve.lifecycle_before,
            "lifecycle_after": reserve.lifecycle_after,
        });
        if let Some(security_digest) = &reserve.security_digest {
            payload["security_digest"] = json!(security_digest);
        }
        let link = lifecycle(&json!({
            "kind": "record", "operation": "seal", "purpose": "link",
            "key": key_hex.as_str(), "payload": payload,
        }))?;
        let text = |name: &str| link[name].as_str().ok_or_else(|| pack(DRAFT_INVALID));
        self.connection
            .execute(
                "insert into extension_command_pack_pending (
                    control_revision, record_json, record_digest, record_mac,
                    link_json, link_digest, link_mac
                 ) values (?, ?, ?, ?, ?, ?, ?)",
                params![
                    revision,
                    reserve.record_json,
                    reserve.record_digest,
                    reserve.record_mac,
                    text("record")?,
                    text("digest")?,
                    text("mac")?,
                ],
            )
            .map_err(store_fault)?;
        Ok(())
    }

    /// The digest of the active activation the draft extends, or none over a
    /// retained baseline.
    fn active_digest(&self, key_hex: &str) -> Res<Option<String>> {
        let current = query_row(
            self.connection,
            "select * from extension_command_pack_activation where singleton = 1",
            [],
        )?
        .ok_or_else(|| pack(ACTIVATION_MISSING))?;
        let baseline = serde_json::from_str::<Value>(&row_str(&current, "record_json")?)
            .is_ok_and(|value| value.get("schema") == Some(&json!(BASELINE_SCHEMA)));
        if baseline {
            let mut request = record_request("baseline", &current, "record")?;
            request["revision"] = json!(row_int(&current, "revision")?);
            verified(key_hex, request)?;
            return Ok(None);
        }
        let previous = verified(key_hex, record_request("activation", &current, "record")?)?;
        if previous["revision"].as_i64() != Some(row_int(&current, "revision")?) {
            return Err(pack(REVISION_INVALID));
        }
        Ok(Some(row_str(&current, "record_digest")?))
    }
}

#[cfg(test)]
#[path = "pack_reserve_tests.rs"]
mod tests;
