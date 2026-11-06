//! The command-pack half of `resume`: `activation_journal.finish` and
//! `activation_store.write_in_transaction`, inside the immediate transaction
//! that commits the anchored control row.
//!
//! The pending activation is authenticated against the transition it was
//! reserved for, then installed in the active slot. Everything protected the
//! activation is checked against comes from the caller, which reads it from
//! the policy-integrity store: the command-pack verifier key, the lifecycle
//! floor, the active security record and, for a link sealed before lifecycle
//! binding, the retained legacy evidence. The resident only writes the store.
//! When the floor still has to move, or the evidence was not sent, it says so
//! and writes nothing; the caller moves the floor and asks again, so the
//! floor always moves before the activation row it admits.

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::records::{degraded, query_row, row_int, row_str, store_fault, Fault, Res, Row};
use super::{Ctx, STORE_UNAVAILABLE};
use crate::local_store_read::table_exists;

const MISSING: &str = "native_command_pack_transition_missing";
const MISMATCH: &str = "native_command_pack_transition_mismatch";
const ACTIVATION_MISSING: &str = "native_command_pack_activation_missing";
const CONFLICT: &str = "native_command_pack_activation_conflict";
const REVISION_INVALID: &str = "native_command_pack_revision_invalid";
const SCHEMA_INVALID: &str = "native_command_pack_schema_invalid";
const BASELINE_SCHEMA: &str = "guard.command-pack-legacy-baseline.v1";
const SCHEMA_V2: &str = "guard.command-pack-activation.v2";
/// `PACK_ACTIVATION_SCHEMA_VERSION` and `PACK_ACTIVATION_V2_SCHEMA_VERSION`.
const PACK_SCHEMA_VERSIONS: [i64; 2] = [5, 6];

/// How far the pack activation got.
pub(super) enum PackStep {
    /// The activation is installed and the pending row removed.
    Finished,
    /// The lifecycle floor must move from `before` to `after` first.
    FloorOwed { before: String, after: String },
    /// The link predates lifecycle binding and the evidence was not sent.
    LegacyOwed,
}

fn pack(reason: &str) -> Fault {
    Fault::Pack(reason.to_owned())
}

/// `lifecycle.invoke`: a refusal is the pack error the caller reports.
fn lifecycle(input: &Value) -> Res<Value> {
    crate::pack_lifecycle::evaluate(input).map_err(Fault::Pack)
}

/// `lifecycle.record`: the verified value. A record that does not
/// authenticate is tampered and one outside its schema is refused by name;
/// a request the runtime could not answer stays retryable.
fn verified(key_hex: &str, mut request: Value) -> Res<Value> {
    request["kind"] = json!("record");
    request["operation"] = json!("verify");
    request["key"] = json!(key_hex);
    let answer = crate::pack_lifecycle::evaluate(&request).map_err(|code| degraded(&code))?;
    let reason = answer["reason"].as_str().unwrap_or(MISMATCH);
    match answer["fault"].as_str() {
        None => Ok(answer["value"].clone()),
        Some("tampered") => Err(Fault::Tampered(reason.to_owned())),
        Some(_) => Err(pack(reason)),
    }
}

fn record_request(purpose: &str, row: &Row, prefix: &str) -> Res<Value> {
    Ok(json!({
        "purpose": purpose,
        "record": row_str(row, &format!("{prefix}_json"))?,
        "digest": row_str(row, &format!("{prefix}_digest"))?,
        "mac": row_str(row, &format!("{prefix}_mac"))?,
    }))
}

/// `extension_control_schema_marker_is_compatible` for a store that has
/// activated packs.
fn marker_version(connection: &rusqlite::Connection) -> Res<i64> {
    let marker = query_row(
        connection,
        "select version, checksum from extension_control_schema_migration where singleton = 1",
        [],
    )?
    .ok_or_else(|| pack(SCHEMA_INVALID))?;
    let version = row_int(&marker, "version").map_err(|_| pack(SCHEMA_INVALID))?;
    let checksum = row_str(&marker, "checksum").map_err(|_| pack(SCHEMA_INVALID))?;
    let expected = hex::encode(Sha256::digest(
        format!("hol-guard.extension-control-authority.schema.v{version}").as_bytes(),
    ));
    if !PACK_SCHEMA_VERSIONS.contains(&version) || checksum != expected {
        return Err(pack(SCHEMA_INVALID));
    }
    Ok(version)
}

impl Ctx<'_> {
    /// Install the activation the anchored row at `row` reserved, bound to
    /// the pack record digest `expected` the authenticated transition names.
    pub(super) fn finish_pack(&self, row: &Row, expected: &Value) -> Res<PackStep> {
        let finish = self
            .request
            .pack_finish
            .as_ref()
            .ok_or_else(|| pack(MISSING))?;
        let key = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&finish.key_b64)
                .map_err(|_| pack("native_command_pack_key_invalid"))?,
        );
        let key_hex = Zeroizing::new(hex::encode(key.as_slice()));
        let revision = row_int(row, "revision")?;
        let journal = table_exists(self.connection, "extension_command_pack_pending")
            .map_err(|_| degraded(STORE_UNAVAILABLE))?;
        let pending = if journal {
            query_row(
                self.connection,
                "select * from extension_command_pack_pending where control_revision = ?",
                [revision],
            )?
        } else {
            None
        };
        let Some(pending) = pending else {
            return Err(pack(MISSING));
        };
        if json!(row_str(&pending, "record_digest")?) != *expected {
            return Err(pack(MISSING));
        }
        // Only a pure authentication failure is eligible for an explicit
        // recovery reset; a runtime that could not answer stays retryable.
        let (header, mut link) =
            self.verified_pending(row, &pending, &key_hex)
                .map_err(|fault| match fault {
                    Fault::Tampered(_) | Fault::Pack(_) => pack(MISMATCH),
                    other => other,
                })?;
        if link.get("lifecycle_before").is_none() {
            let Some(evidence) = finish.legacy_evidence.as_ref() else {
                return Ok(PackStep::LegacyOwed);
            };
            let Value::Object(mut request) = evidence.clone() else {
                return Err(pack("pack_lifecycle_legacy_invalid"));
            };
            request.insert("kind".into(), json!("legacy-pending"));
            request.insert("key".into(), json!(key_hex.as_str()));
            request.insert("floor".into(), json!(finish.floor));
            let recovered = lifecycle(&Value::Object(request))?;
            for (name, value) in recovered.as_object().into_iter().flatten() {
                link[name] = value.clone();
            }
        }
        let (Some(before), Some(after)) = (
            link["lifecycle_before"].as_str(),
            link["lifecycle_after"].as_str(),
        ) else {
            return Err(pack(MISMATCH));
        };
        self.check_activation(&header, &link, &key_hex)?;
        let floor = finish
            .floor
            .as_deref()
            .ok_or_else(|| pack("pack_lifecycle_protected_floor_missing"))?;
        lifecycle(&json!({"kind": "read", "key": key_hex.as_str(), "floor": floor}))?;
        if floor != after {
            if floor == before {
                return Ok(PackStep::FloorOwed {
                    before: before.to_owned(),
                    after: after.to_owned(),
                });
            }
            return Err(pack("pack_lifecycle_prepared_floor_conflict"));
        }
        self.connection
            .execute(
                "insert into extension_command_pack_activation
                 (singleton, revision, record_json, record_digest, record_mac, recorded_at)
                 values (1, ?, ?, ?, ?, ?)
                 on conflict(singleton) do update set revision = excluded.revision,
                     record_json = excluded.record_json, record_digest = excluded.record_digest,
                     record_mac = excluded.record_mac, recorded_at = excluded.recorded_at",
                params![
                    header["revision"].as_i64(),
                    row_str(&pending, "record_json")?,
                    row_str(&pending, "record_digest")?,
                    row_str(&pending, "record_mac")?,
                    row_str(row, "created_at")?,
                ],
            )
            .map_err(store_fault)?;
        self.connection
            .execute(
                "delete from extension_command_pack_pending where control_revision = ?",
                [revision],
            )
            .map_err(store_fault)?;
        Ok(PackStep::Finished)
    }

    /// `_verify_pending`: the link binds this transition and pack record, and
    /// the pack record binds this catalog.
    fn verified_pending(&self, row: &Row, pending: &Row, key_hex: &str) -> Res<(Value, Value)> {
        let mut link = record_request("link", pending, "link")?;
        link["expected"] = json!({
            "control_revision": row_int(row, "revision")?,
            "snapshot_digest": row_str(row, "snapshot_digest")?,
            "catalog_digest": row_str(row, "catalog_digest")?,
            "pack_record_digest": row_str(pending, "record_digest")?,
        });
        let link = verified(key_hex, link)?;
        let header = verified(key_hex, record_request("activation", pending, "record")?)?;
        if header["catalog_digest"] != json!(row_str(row, "catalog_digest")?) {
            return Err(pack(MISMATCH));
        }
        if !link.is_object() || !header.is_object() {
            return Err(pack(MISMATCH));
        }
        Ok((header, link))
    }

    /// `write_in_transaction` up to the floor: the draft is still admitted,
    /// extends the active slot by one revision and keeps the security scope it
    /// was prepared under.
    fn check_activation(&self, header: &Value, link: &Value, key_hex: &str) -> Res<()> {
        let now = link["admitted_at"]
            .as_i64()
            .ok_or_else(|| pack("native_command_pack_draft_expired"))?;
        let admission = lifecycle(&json!({
            "kind": "admission",
            "profile": header.get("authority_profile").cloned().unwrap_or(json!("remote")),
            "issued_at": header["issued_at"],
            "expires_at": header["expires_at"],
            "now": now,
        }))?;
        if admission["current"] != json!(true) {
            return Err(pack("native_command_pack_draft_expired"));
        }
        let version = marker_version(self.connection)?;
        if header["schema"] == SCHEMA_V2 && version < PACK_SCHEMA_VERSIONS[1] {
            return Err(pack(SCHEMA_INVALID));
        }
        let current = query_row(
            self.connection,
            "select * from extension_command_pack_activation where singleton = 1
             and length(cast(record_json as blob)) between 1 and 65536
             and length(record_digest) = 64 and length(record_mac) = 64",
            [],
        )?
        .ok_or_else(|| pack(ACTIVATION_MISSING))?;
        let baseline = serde_json::from_str::<Value>(&row_str(&current, "record_json")?)
            .is_ok_and(|value| value.get("schema") == Some(&json!(BASELINE_SCHEMA)));
        let (previous_digest, revision) = if baseline {
            let mut request = record_request("baseline", &current, "record")?;
            request["revision"] = json!(row_int(&current, "revision")?);
            verified(key_hex, request)?;
            (Value::Null, 1)
        } else {
            let previous = verified(key_hex, record_request("activation", &current, "record")?)?;
            let revision = previous["revision"]
                .as_i64()
                .ok_or_else(|| pack(REVISION_INVALID))?;
            (json!(row_str(&current, "record_digest")?), revision + 1)
        };
        if header["previous_digest"] != previous_digest {
            return Err(pack(CONFLICT));
        }
        if header["revision"].as_i64() != Some(revision) {
            return Err(pack(REVISION_INVALID));
        }
        let expected = link.get("security_digest").cloned().unwrap_or(Value::Null);
        let security = self
            .request
            .pack_finish
            .as_ref()
            .and_then(|finish| finish.security.clone());
        crate::active_pack_security::evaluate(&json!({
            "operation": "check",
            "key": key_hex,
            "record": security,
            "expected": expected,
        }))
        .map_err(Fault::Pack)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "pack_finish_tests.rs"]
mod tests;
