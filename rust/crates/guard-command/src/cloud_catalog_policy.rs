//! Bounded policy selection from a pinned complete local view. This grants no
//! publisher trust and never installs or enables an extension.
use super::*;
use std::collections::BTreeSet;

/// `expected` comes from the current authenticated local discovery/active
/// adapters, never from a policy response. Private identity is checked by the
/// session adapter; it is deliberately absent from the content-addressed cache.
pub fn select_policy_metadata(
    home: &Path,
    token: &str,
    expected: &Observation,
    view_digest: &str,
    extension_ids: &BTreeSet<String>,
    permission_ids: &BTreeSet<String>,
) -> Result<Vec<Value>> {
    expected.validate()?;
    if expected.guard_home != home
        || !sha(token)
        || !sha(view_digest)
        || extension_ids.len() + permission_ids.len() > 1024
        || extension_ids.iter().any(|id| !projection::identity(id))
        || permission_ids.iter().any(|id| !projection::identity(id))
    {
        return Err(Error::Invalid);
    }
    let root = cache::directory(home)?;
    let lock = cache::lock_file(&root.join("cache.lock"))?;
    fs2::FileExt::lock_shared(&lock)?;
    let path = root.join(token);
    let record = cache::record(&path)?;
    if digest(&record["manifest"])? != token
        || record["observation"] != serde_json::to_value(expected).map_err(|_| Error::Invalid)?
        || record["manifest"]["catalogDigest"] != view_digest
        || record["manifest"]["enforcementCatalogDigest"] != expected.enforcement_catalog_digest
        || record["manifest"]["generatedAt"] != expected.generated_at
    {
        return Err(Error::Invalid);
    }
    // Validate the entire chain, including pages after the requested owners.
    cache::verify(&path, &record)?;
    let mut selected = Vec::new();
    let mut found_extensions = BTreeSet::new();
    let mut found_permissions = BTreeSet::new();
    let mut bytes = 0;
    for ordinal in 0..record["hashes"].as_array().ok_or(Error::Invalid)?.len() {
        let page: Value = serde_json::from_slice(&cache::page(&path, &record, ordinal)?)
            .map_err(|_| Error::Invalid)?;
        for entry in page["entries"].as_array().ok_or(Error::Invalid)? {
            let id = entry["id"].as_str().ok_or(Error::Invalid)?;
            let requested_extension = extension_ids.contains(id);
            if requested_extension {
                found_extensions.insert(id.to_owned());
            }
            let mut requested_permission = false;
            for permission in entry["permissions"].as_array().ok_or(Error::Invalid)? {
                let pid = permission["id"].as_str().ok_or(Error::Invalid)?;
                if permission_ids.contains(pid) {
                    found_permissions.insert(pid.to_owned());
                    requested_permission = true;
                }
            }
            if requested_extension || requested_permission {
                // Reject malformed/substituted cache metadata even if its hash
                // chain is internally consistent.
                if projection::validate(entry)? != *entry {
                    return Err(Error::Invalid);
                }
                bytes += encode(entry)?.len();
                if bytes > 1_000_000 {
                    return Err(Error::Limit);
                }
                selected.push(entry.clone());
            }
        }
    }
    if &found_extensions != extension_ids || &found_permissions != permission_ids {
        return Err(Error::Unavailable);
    }
    Ok(selected)
}
