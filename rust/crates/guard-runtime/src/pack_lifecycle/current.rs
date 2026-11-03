//! Independent discovery high-water mark. Never changes activation identity.
use super::*;
use sha2::{Digest, Sha256};

pub(super) fn evaluate(input: &Value, active: &Floor, key: &[u8]) -> Result<Value, String> {
    let cursor = input["cursor"]
        .as_str()
        .map(|s| decode(s, key))
        .transpose()?;
    let retained = cursor.as_ref().and_then(|f| f.remote.as_ref());
    if input["publication"].is_null() {
        let complete = input["complete"]
            .as_str()
            .map(|s| decode(s, key))
            .transpose()?;
        let keep: BTreeSet<_> = retained
            .into_iter()
            .chain(complete.as_ref().and_then(|f| f.remote.as_ref()))
            .map(|i| i.root.as_str())
            .collect();
        let mut remove = Vec::new();
        if let Some(files) = input["files"].as_array() {
            if files.len() > 8192 {
                return Err("discovery_current_cache_bounds".into());
            }
            for file in files {
                let name = file.as_str().ok_or("discovery_current_cache_invalid")?;
                let digest = name
                    .strip_suffix(".root")
                    .or_else(|| name.strip_suffix(".provenance"));
                if let Some(digest) = digest.filter(|d| hex(d, 64)) {
                    if !keep.contains(digest) {
                        remove.push(name);
                    }
                }
            }
        }
        return Ok(json!({"retained":retained,"remove":remove}));
    }
    // Only the fixed verified remote factory supplies this bounded string.
    let data = input["publication"]
        .as_str()
        .ok_or("discovery_current_root_invalid")?;
    if data.is_empty() || data.len() > 65536 {
        return Err("discovery_current_root_invalid".into());
    }
    let root: Value = serde_json::from_str(data).map_err(|_| "discovery_current_root_invalid")?;
    let engine = guard_command::source_cli::compiler_info()["implementation_digest"].clone();
    if root["schema"] != "guard.extension-distribution.v2" || root["engine"] != engine {
        return Err("discovery_current_engine_incompatible".into());
    }
    let admission = evaluate_admission(input, &root)?;
    if !admission {
        return Err("discovery_current_authority_expired".into());
    }
    let candidate = Identity {
        profile: "remote".into(),
        source: root["source_sha"]
            .as_str()
            .ok_or("discovery_current_root_invalid")?
            .into(),
        engine: root["engine"]
            .as_str()
            .ok_or("discovery_current_root_invalid")?
            .into(),
        root: hex::encode(Sha256::digest(data.as_bytes())),
        version: root["publication_id"]
            .as_str()
            .ok_or("discovery_current_root_invalid")?
            .into(),
        authority: root["authority_epoch"]
            .as_u64()
            .ok_or("discovery_current_root_invalid")?,
        revocation: root["policy"]["revocations"]["epoch"]
            .as_u64()
            .ok_or("discovery_current_root_invalid")?,
    };
    candidate.validate()?;
    // Installed 0.0 has no remote authority, even when copied into a remote
    // envelope. Real publications start above the sentinel.
    if version::compare("remote", &candidate.version, "0.0")?.is_le() {
        return Err("discovery_current_remote_authority_required".into());
    }
    let security = input["security"]
        .as_str()
        .map(|s| crate::active_pack_security::Security::decode(s, key))
        .transpose()?;
    if let Some(security) = &security {
        security.check_discovery(&root)?;
    }
    if input["restore"] == true {
        let complete = decode(
            input["complete"]
                .as_str()
                .ok_or("discovery_current_complete_missing")?,
            key,
        )?;
        if complete.remote.as_ref() != Some(&candidate)
            || candidate.authority < active.authority
            || candidate.revocation < active.revocation
        {
            return Err("discovery_current_complete_mismatch".into());
        }
        let observed = retained.ok_or("discovery_current_observation_missing")?;
        let order = version::compare("remote", &candidate.version, &observed.version)?;
        if order.is_gt()
            || (order.is_eq() && candidate != *observed)
            || candidate.authority > observed.authority
            || candidate.revocation > observed.revocation
        {
            return Err("discovery_current_complete_mismatch".into());
        }
        // Restore only this previously completed view, never its authority as
        // a new activation or a lower observation cursor. Known negative facts
        // above still forbid restoring an inapplicable security epoch.
        return Ok(json!({"view":true}));
    }
    let security_floor = security
        .as_ref()
        .map(|s| decode(s.lineage_floor(), key))
        .transpose()?;
    let mut next = None;
    for (name, floor) in [
        ("active", Some(active)),
        ("cursor", cursor.as_ref()),
        ("security", security_floor.as_ref()),
    ] {
        let Some(floor) = floor else { continue };
        match transition(floor, &candidate, &input[format!("{name}_ancestry")]) {
            Ok(value) => {
                if name == "cursor" || next.is_none() {
                    next = Some(value);
                }
            }
            Err(code)
                if code == "pack_lifecycle_source_ancestry_required"
                    && input[format!("{name}_ancestry")].is_null() =>
            {
                return Ok(
                    json!({"lineage_kind":name,"lineage_floor":encode(floor,key)?,
                    "lineage_source":candidate.source}),
                );
            }
            Err(code) => return Err(code),
        }
    }
    Ok(
        json!({"record":encode(&next.ok_or("discovery_current_floor_missing")?,key)?,
        "identity":candidate}),
    )
}

fn evaluate_admission(input: &Value, root: &Value) -> Result<bool, String> {
    let result = super::evaluate(&json!({"kind":"admission","profile":"remote",
        "now":input["now"],"issued_at":root["issued_at"],"expires_at":root["expires_at"]}))?;
    Ok(result["current"] == true)
}

#[cfg(test)]
mod tests;
