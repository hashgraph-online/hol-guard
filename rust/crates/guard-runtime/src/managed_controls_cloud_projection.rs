//! Signed Cloud projection bytes. Provenance authenticates the local selection
//! but is intentionally excluded from the proof, so disabled discovery growth
//! cannot change a delivery. No activation or publisher trust is derived here.
use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

fn canonical(value: &Value, v2: bool) -> Result<String, &'static str> {
    let bytes = if v2 {
        crate::policy_bundle_json::v2_canonical_bytes(value)?
    } else {
        let mut bytes = Vec::new();
        guard_contracts::write_canonical_json(value, &mut bytes)?;
        bytes
    };
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("policy_projection_limit");
    }
    String::from_utf8(bytes).map_err(|_| ERR_REQUEST)
}

pub(super) fn proof(
    parsed: &Value,
    digest: &str,
    metadata: Option<&[Value]>,
) -> Result<Value, &'static str> {
    if !crate::policy_bundle_py::is_hex64(digest) {
        return Err("policy_enforcement_digest_invalid");
    }
    let v2 = metadata.is_some();
    let layers = if parsed["signed_cloud_layer"].is_null() {
        json!([])
    } else {
        json!([{"schema_version":"1.0.0", "kind":"signed-cloud",
            "catalog_digest":digest,
            "global_lockdown":parsed["signed_cloud_layer"]["global_lockdown"],
            "controls":parsed["signed_cloud_layer"]["controls"]}])
    };
    let rules = parsed["rule_targets"]
        .as_array()
        .ok_or(ERR_REQUEST)?
        .iter()
        .map(|rule| {
            json!({"ruleId":rule["rule_id"],
            "extensionIds":rule["extension_ids"],"permissionIds":rule["permission_ids"]})
        })
        .collect::<Vec<_>>();
    let delegated = parsed["delegated_targets"]
        .as_array()
        .ok_or(ERR_REQUEST)?
        .iter()
        .map(|target| {
            json!({"targetKind":target["target_kind"],
            "targetId":target["target_id"],"enforcementOwner":"package-firewall"})
        })
        .collect::<Vec<_>>();
    let mut projection = json!({
        "schemaVersion":if v2 {"guard.signed-cloud-extension-projection.v2"}
            else {"guard.signed-cloud-extension-projection.v1"},
        "authorityMode":parsed["authority_mode"],
        "signedCloudLayersJson":canonical(&layers,v2)?,
        "ruleTargets":rules,"delegatedTargets":delegated});
    if let Some(metadata) = metadata {
        projection["enforcementCatalogDigest"] = json!(digest);
        projection["targetMetadata"] = json!(metadata);
    }
    let canonical_json = canonical(&projection, v2)?;
    let digest = format!("sha256:{:x}", Sha256::digest(canonical_json.as_bytes()));
    Ok(json!({"canonical_json":canonical_json,"digest":digest}))
}

fn targets(document: &Value) -> Result<(BTreeSet<String>, BTreeSet<String>), &'static str> {
    let mut extensions = BTreeSet::new();
    let mut permissions = BTreeSet::new();
    let mut insert = |kind: Kind, raw: &Value| -> Result<(), &'static str> {
        let id = canonical_id(Some(raw), kind).map_err(|_| ERR_REQUEST)?;
        match kind {
            Kind::Extension => {
                extensions.insert(id);
            }
            Kind::Permission => {
                permissions.insert(id);
            }
        }
        Ok(())
    };
    if let Some(layer) = document.get(CONTROLS_FIELD) {
        for control in layer["controls"].as_array().ok_or(ERR_REQUEST)? {
            let kind = match control["targetKind"].as_str() {
                Some("extension") => Kind::Extension,
                Some("permission") => Kind::Permission,
                _ => return Err(ERR_REQUEST),
            };
            insert(kind, &control["targetId"])?;
        }
    }
    for rule in document["spec"]["rules"].as_array().ok_or(ERR_REQUEST)? {
        if let Some(target) = rule.get(TARGETS_FIELD) {
            for (field, kind) in [
                ("extensionIds", Kind::Extension),
                ("permissionIds", Kind::Permission),
            ] {
                for id in target[field].as_array().ok_or(ERR_REQUEST)? {
                    insert(kind, id)?;
                }
            }
        }
    }
    if extensions.len() + permissions.len() > MAX_CONTROL_SET_TARGETS {
        return Err("policy_target_limit");
    }
    Ok((extensions, permissions))
}

/// Local-only observation from the session/discovery adapter. A response may
/// supply neither a home/path nor an enforcement identity to this function.
pub(super) fn selected(request: &Obj, document: &Value) -> Result<Vec<Value>, &'static str> {
    let local = request.get("cloud_view").ok_or(ERR_REQUEST)?;
    guard_command::cloud_catalog::completion::validate(
        Path::new(local["guard_home"].as_str().ok_or(ERR_REQUEST)?),
        local,
    )
    .map_err(|_| "policy_completed_observation_invalid")?;
    let observation: guard_command::cloud_catalog::Observation =
        serde_json::from_value(local["observation"].clone()).map_err(|_| ERR_REQUEST)?;
    let text = |key: &str| {
        local[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(ERR_REQUEST)
    };
    let now = crate::policy_bundle_time::strict_utc_micros(text("now")?)
        .ok_or("policy_observation_time_invalid")?;
    let observed = crate::policy_bundle_time::strict_utc_micros(text("observed_at")?)
        .ok_or("policy_observation_time_invalid")?;
    if now < observed || now - observed > 900_000_000 {
        return Err("policy_observation_stale");
    }
    // Optional selected server metadata can be checked, but can never replace
    // the local complete view or its authenticated identity.
    let identity = local["identity"].as_object().ok_or(ERR_REQUEST)?;
    if identity.len() != 4
        || ["ownerUserId", "workspaceId", "deviceId", "runtimeId"]
            .iter()
            .any(|key| {
                identity
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.is_empty() || s.len() > 128)
            })
    {
        return Err("policy_observation_identity_invalid");
    }
    let (extensions, permissions) = targets(document)?;
    let selected = guard_command::cloud_catalog::select_policy_metadata(
        Path::new(text("guard_home")?),
        text("token")?,
        &observation,
        text("view_digest")?,
        &extensions,
        &permissions,
    )
    .map_err(|_| "policy_local_view_invalid")?;
    if let Some(metadata) = request.get("target_metadata") {
        let mut provenance = json!(identity);
        provenance["viewDigest"] = json!(text("view_digest")?);
        provenance["enforcementDigest"] = json!(observation.enforcement_catalog_digest);
        provenance["observedAt"] = json!(text("observed_at")?);
        if *metadata
            != json!({"kind":"policy-target-metadata.v2",
            "provenance":provenance,"extensions":selected})
        {
            return Err("policy_target_metadata_mismatch");
        }
    }
    Ok(selected)
}

/// Retain authenticated inactive target facts without changing the active
/// registry or its enforcement digest. Active required floors win every time.
pub(super) fn extend_catalog(
    catalog: &mut Catalog,
    metadata: &[Value],
) -> Result<(), &'static str> {
    for entry in metadata {
        let id = entry["id"].as_str().ok_or(ERR_REQUEST)?;
        let delegated = !entry["delegatedProtection"].is_null();
        catalog
            .extensions
            .entry(id.to_owned())
            .or_insert(Extension {
                required: false,
                delegated,
            });
        for permission in entry["permissions"].as_array().ok_or(ERR_REQUEST)? {
            let pid = permission["id"].as_str().ok_or(ERR_REQUEST)?;
            catalog
                .permissions
                .entry(pid.to_owned())
                .or_insert(Permission {
                    extension_id: id.to_owned(),
                    owner_delegated: Some(delegated),
                    configurable: permission["configurable"].as_bool().ok_or(ERR_REQUEST)?,
                });
        }
    }
    Ok(())
}

pub(super) fn evaluate(
    request: &Obj,
    _document: &Value,
    parsed: Value,
    selected_metadata: Option<&[Value]>,
) -> Result<Value, &'static str> {
    let projection = request.get("projection").ok_or(ERR_REQUEST)?;
    let digest = projection["catalog_digest"].as_str().ok_or(ERR_REQUEST)?;
    let metadata = match projection["version"].as_u64() {
        Some(1) => None,
        Some(2) => {
            // A caller that observed a delivery envelope binds its catalog
            // digest here. An absent key means no envelope accompanied this
            // document; a null one means the envelope carried no usable digest.
            let delivery = request
                .get("delivery_catalog_digest")
                .map(|value| value.as_str() == Some(digest));
            if request["cloud_view"]["observation"]["enforcement_catalog_digest"] != digest
                || request
                    .get("enforcement_catalog_digest")
                    .and_then(Value::as_str)
                    != Some(digest)
                || delivery == Some(false)
            {
                return Err("policy_enforcement_digest_mismatch");
            }
            Some(selected_metadata.ok_or(ERR_REQUEST)?)
        }
        _ => return Err(ERR_REQUEST),
    };
    Ok(json!({"ok":parsed,"projection":proof(&parsed,digest,metadata)?}))
}

#[cfg(test)]
#[path = "managed_controls_cloud_projection_tests.rs"]
mod tests;
