//! Request-local control metadata: no executable selection or policy hydration.
use super::*;

pub(super) fn prepare(input: &Value) -> Result<Value> {
    let mut missing = BTreeSet::new();
    for row in input["controls"].as_array().ok_or_else(invalid)? {
        let permission = row["kind"] == "permission";
        if row[if permission {
            "permission_present"
        } else {
            "extension_present"
        }] == true
        {
            continue;
        }
        let identity = row["id"].as_str().ok_or_else(invalid)?;
        let identity = if permission {
            identity
                .split_once(".permission.")
                .map_or(identity, |(owner, _)| owner)
        } else {
            identity
        };
        if valid_id(identity) {
            missing.insert(identity.to_owned());
        }
        if missing.len() > MAX_SELECTED {
            return Err("control metadata expansion exceeds admission budget".into());
        }
    }
    if missing.is_empty() {
        return Ok(json!({"catalog_refs":[]}));
    }
    if input.get("installed").is_none() {
        return Ok(json!({"authority":"installed"}));
    }
    if input["installed"].is_null() && input["committed"] == false {
        // Legacy installs cannot expand targets from discovery alone.
        return Ok(json!({"catalog_refs":[]}));
    }
    let directory = Path::new(input["directory"].as_str().ok_or_else(invalid)?);
    let mut catalogs = Vec::new();
    let mut catalog_bytes = 0;
    for profile in ["installed", "remote"] {
        if missing.is_empty() {
            break;
        }
        let Some(publication) = input.get(profile) else {
            return Ok(json!({"authority":profile}));
        };
        if publication.is_null() {
            continue;
        }
        let data = publication
            .as_str()
            .filter(|s| s.len() <= 65536)
            .ok_or_else(invalid)?;
        let root: Value = serde_json::from_str(data).map_err(|_| invalid())?;
        for identity in missing.clone() {
            let Some(record) = metadata::lookup(directory, &root, &identity, None)? else {
                continue;
            };
            let catalog = proofs::object(directory, &record["catalog_metadata"])?;
            catalog_bytes += encoded(&catalog)?.len();
            if catalog_bytes > 128 * 1024 * 1024 {
                return Err("target metadata admission budget exceeded".into());
            }
            let list = catalog
                .as_array()
                .filter(|a| a.len() == 1)
                .ok_or_else(|| Failure::from("target catalog shape invalid"))?;
            let value = &list[0];
            if value["extension_id"] != identity
                || ["dependencies", "trust_class", "required", "activation"]
                    .iter()
                    .any(|field| value[*field] != record[*field])
            {
                return Err("target metadata differs from authenticated availability".into());
            }
            // Permission ownership is authenticated by this catalog, never by
            // the inferred prefix alone. TargetMetadata.permission performs the
            // existing DTO lookup, including the absent-permission result.
            catalogs.push(record["catalog_metadata"].clone());
            missing.remove(&identity);
        }
    }
    Ok(json!({"catalog_refs":catalogs}))
}
