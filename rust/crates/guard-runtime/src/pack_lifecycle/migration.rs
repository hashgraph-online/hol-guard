//! One-time legacy admission requires the retained credential-store anchor,
//! not a database's assertion that it was once enrolled.
use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn authenticated(envelope: &Value, key: &[u8], purpose: &str) -> Result<Value, String> {
    let data = envelope["record"]
        .as_str()
        .ok_or("pack_lifecycle_legacy_invalid")?;
    if data.is_empty() || data.len() > 512 * 1024 {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    let mut derive =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "pack_lifecycle_key_invalid")?;
    derive.update(b"hol-guard.extension-control-authority.v1\0");
    derive.update(purpose.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&derive.finalize().into_bytes())
        .map_err(|_| "pack_lifecycle_key_invalid")?;
    mac.update(data.as_bytes());
    let signature = hex::decode(
        envelope["mac"]
            .as_str()
            .ok_or("pack_lifecycle_legacy_invalid")?,
    )
    .map_err(|_| "pack_lifecycle_legacy_invalid")?;
    mac.verify_slice(&signature)
        .map_err(|_| "pack_lifecycle_legacy_authentication_failed")?;
    if envelope["digest"] != hex::encode(Sha256::digest(data.as_bytes())) {
        return Err("pack_lifecycle_legacy_authentication_failed".into());
    }
    let value: Value = serde_json::from_str(data).map_err(|_| "pack_lifecycle_legacy_invalid")?;
    if value["authority_schema_version"] != 1 || value["purpose"] != purpose {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    Ok(value)
}

fn pack(envelope: &Value, key: &[u8]) -> Result<Option<Identity>, String> {
    if envelope.is_null() {
        return Ok(None);
    }
    let header = authenticated(envelope, key, "command-pack-activation.v1")?;
    // The previous writer only issued remote v1 activations. New installed
    // records must never be relabelled as legacy evidence.
    if header["schema"] != "guard.command-pack-activation.v1"
        || header["revision"].as_u64().is_none_or(|n| n == 0)
        || header["issued_at"].as_u64().is_none()
        || header["expires_at"].as_u64().is_none()
    {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    let identity = Identity {
        profile: "remote".into(),
        source: header["source_sha"].as_str().unwrap_or_default().into(),
        engine: header["engine"].as_str().unwrap_or_default().into(),
        root: header["root_digest"].as_str().unwrap_or_default().into(),
        version: header["publication_id"].as_str().unwrap_or_default().into(),
        authority: header["authority_epoch"].as_u64().unwrap_or_default(),
        revocation: header["revocation_epoch"]
            .as_u64()
            .ok_or("pack_lifecycle_legacy_invalid")?,
    };
    identity.validate()?;
    Ok(Some(identity))
}

// All authority comes from the retained anchor, never the SQL phase column.
fn evidence(input: &Value, key: &[u8]) -> Result<Vec<Identity>, String> {
    let legacy_key = hex::decode(
        input["legacy_key"]
            .as_str()
            .ok_or("pack_lifecycle_key_invalid")?,
    )
    .map_err(|_| "pack_lifecycle_key_invalid")?;
    if legacy_key.len() != 32 {
        return Err("pack_lifecycle_key_invalid".into());
    }
    let anchor = authenticated(
        &input["legacy_anchor"],
        &legacy_key,
        "extension-control.anchor",
    )?;
    let mut snapshot = authenticated(
        &input["legacy_snapshot"],
        &legacy_key,
        "extension-control.snapshot",
    )?;
    if anchor["revision"].as_u64().is_none() || snapshot["revision"].as_u64().is_none() {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    let pending = &input["legacy_pending"];
    let mut result = Vec::new();
    if !pending.is_null() {
        let control = authenticated(
            &input["legacy_transition"],
            &legacy_key,
            "extension-control.transition",
        )?;
        let next = authenticated(
            &input["legacy_next_snapshot"],
            &legacy_key,
            "extension-control.snapshot",
        )?;
        let link = authenticated(&pending["link"], key, "command-pack-control-transition.v1")?;
        let header = authenticated(&pending["activation"], key, "command-pack-activation.v1")?;
        let digest = &pending["activation"]["digest"];
        let admitted = link["admitted_at"]
            .as_u64()
            .ok_or("pack_lifecycle_legacy_invalid")?;
        if !matches!(anchor["phase"].as_str(), Some("anchored" | "committed"))
            || anchor["revision"] != next["revision"]
            || anchor["snapshot_digest"] != input["legacy_next_snapshot"]["digest"]
            || control["phase"] != "prepared"
            || control["revision"] != next["revision"]
            || control["previous_revision"]
                .as_u64()
                .and_then(|n| n.checked_add(1))
                != next["revision"].as_u64()
            || control["previous_revision"] != snapshot["revision"]
            || control["previous_digest"] != input["legacy_snapshot"]["digest"]
            || next["previous_digest"] != input["legacy_snapshot"]["digest"]
            || control["snapshot_digest"] != input["legacy_next_snapshot"]["digest"]
            || control["catalog_digest"] != next["catalog_digest"]
            || control["command_pack_record_digest"] != *digest
            || next["command_pack_record_digest"] != *digest
            || link.as_object().is_none_or(|m| m.len() != 7)
            || link["control_revision"] != next["revision"]
            || link["snapshot_digest"] != input["legacy_next_snapshot"]["digest"]
            || link["catalog_digest"] != next["catalog_digest"]
            || link["pack_record_digest"] != *digest
            || header["catalog_digest"] != next["catalog_digest"]
            || header["issued_at"].as_u64().is_none_or(|n| n > admitted)
            || header["expires_at"].as_u64().is_none_or(|n| admitted >= n)
        {
            return Err("pack_lifecycle_legacy_anchor_mismatch".into());
        }
    } else if anchor["phase"] != "committed"
        || anchor["revision"].as_u64().is_none()
        || anchor["revision"] != snapshot["revision"]
        || anchor["snapshot_digest"] != input["legacy_snapshot"]["digest"]
    {
        return Err("pack_lifecycle_legacy_anchor_mismatch".into());
    }
    let active = pack(&input["legacy_activation"], key)?;
    // Packless control edits retain the last pack. Walk authenticated
    // snapshot predecessors to the most recent pack-bearing commit.
    if snapshot["command_pack_record_digest"].is_null() {
        for previous in input["legacy_history"]
            .as_array()
            .ok_or("pack_lifecycle_legacy_invalid")?
        {
            if snapshot["previous_digest"] != previous["digest"] {
                return Err("pack_lifecycle_legacy_anchor_mismatch".into());
            }
            let prior = authenticated(previous, &legacy_key, "extension-control.snapshot")?;
            if prior["revision"].as_u64().and_then(|n| n.checked_add(1))
                != snapshot["revision"].as_u64()
            {
                return Err("pack_lifecycle_legacy_anchor_mismatch".into());
            }
            snapshot = prior;
            if !snapshot["command_pack_record_digest"].is_null() {
                break;
            }
        }
    }
    if snapshot["command_pack_record_digest"] != input["legacy_activation"]["digest"]
        || (snapshot["command_pack_record_digest"].is_null()
            && snapshot["revision"].as_u64().is_none_or(|n| n > 1))
    {
        return Err("pack_lifecycle_legacy_anchor_mismatch".into());
    }
    if let Some(active) = active {
        result.push(active);
    }
    if !pending.is_null() {
        let header = authenticated(&pending["activation"], key, "command-pack-activation.v1")?;
        let active = &input["legacy_activation"];
        let revision = if active.is_null() {
            0
        } else {
            authenticated(active, key, "command-pack-activation.v1")?["revision"]
                .as_u64()
                .ok_or("pack_lifecycle_legacy_invalid")?
        };
        if header["previous_digest"] != active["digest"]
            || revision.checked_add(1) != header["revision"].as_u64()
        {
            return Err("pack_lifecycle_legacy_anchor_mismatch".into());
        }
        result.push(pack(&pending["activation"], key)?.ok_or("pack_lifecycle_legacy_invalid")?);
    }
    Ok(result)
}

fn retain(floor: &mut Floor, identity: Identity) -> Result<(), String> {
    if let Some(previous) = &floor.remote {
        if identity.authority < previous.authority || identity.revocation < previous.revocation {
            return Err("pack_lifecycle_epoch_rollback".into());
        }
        let order = version::compare("remote", &identity.version, &previous.version)?;
        if order.is_lt() {
            return Err("pack_lifecycle_version_rollback".into());
        }
        if order.is_eq() && identity != *previous {
            return Err("pack_lifecycle_version_reused".into());
        }
    }
    floor.source = identity.source.clone();
    floor.authority = floor.authority.max(identity.authority);
    floor.revocation = floor.revocation.max(identity.revocation);
    floor.remote = Some(identity);
    Ok(())
}

pub(super) fn recover(input: &Value, key: &[u8]) -> Result<Value, String> {
    let record = input["floor"]
        .as_str()
        .ok_or("pack_lifecycle_protected_floor_missing")?;
    let mut floor = decode(record, key)?;
    let identities = evidence(input, key)?;
    if input["legacy_pending"].is_null() {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    // Recovery may only replay the exact admitted head retained by migration.
    let identity = identities.last().ok_or("pack_lifecycle_legacy_invalid")?;
    if floor.remote.as_ref() != Some(identity) {
        return Err("pack_lifecycle_legacy_below_floor".into());
    }
    retain(&mut floor, identity.clone())?;
    Ok(json!({"lifecycle_before":record,"lifecycle_after":record}))
}

pub(super) fn migrate(input: &Value, key: &[u8]) -> Result<Value, String> {
    let stamp = "guard.command-pack-enrolled.v1";
    if !input["floor"].is_null() && !input["floor"].is_string() {
        return Err("pack_lifecycle_floor_invalid".into());
    }
    if let Some(record) = input["floor"].as_str() {
        decode(record, key)?;
        if !input["stamp"].is_null() && input["stamp"] != stamp {
            return Err("pack_lifecycle_enrollment_stamp_invalid".into());
        }
        return Ok(json!({"record":record,"stamp":stamp}));
    }
    if !input["stamp"].is_null() {
        return Err("pack_lifecycle_protected_floor_missing".into());
    }
    if input["legacy_anchor"].is_null() && input["legacy_snapshot"].is_null() {
        return Ok(json!({"record":null,"stamp":null}));
    }
    let candidate = release::identity(input)?;
    admit(input, key, candidate)
}

pub(super) fn admit(input: &Value, key: &[u8], candidate: Identity) -> Result<Value, String> {
    let identities = evidence(input, key)?;
    let mut floor = Floor {
        schema: "guard.command-pack-floor.v1".into(),
        source: candidate.source.clone(),
        authority: candidate.authority,
        revocation: candidate.revocation,
        installed: Some(candidate),
        remote: None,
    };
    for identity in identities {
        retain(&mut floor, identity)?;
    }
    let record = encode(&floor, key)?;
    Ok(json!({"record":record,"stamp":"guard.command-pack-enrolled.v1"}))
}
