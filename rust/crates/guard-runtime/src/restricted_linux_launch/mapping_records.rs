//! Exact mapping-image evidence; aliases cannot overlap across images.
use super::mounts::path;
use super::BoundaryResult as Result;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

pub(super) struct Record {
    pub path: PathBuf,
    pub identity: [u64; 5],
    pub digest: String,
    pub aliases: Vec<PathBuf>,
}

pub(super) fn validate(value: &Value, approved: &BTreeSet<PathBuf>) -> Result<Vec<Record>> {
    let values = value
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .ok_or("Invalid executable mapping count.")?;
    let mut seen = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut total = 0u64;
    let mut result = Vec::with_capacity(values.len());
    for record in values {
        let fields = record
            .as_object()
            .filter(|v| {
                v.len() == 4
                    && ["path", "identity", "sha256", "targets"]
                        .iter()
                        .all(|k| v.contains_key(*k))
            })
            .ok_or("Invalid executable mapping fields.")?;
        let image = path(
            fields["path"]
                .as_str()
                .ok_or("Invalid executable mapping path.")?,
        )?;
        if !approved.contains(&image) || !seen.insert(image.clone()) {
            return Err("Unbound executable mapping.");
        }
        let values = fields["identity"]
            .as_array()
            .filter(|v| v.len() == 5)
            .ok_or("Invalid executable mapping identity.")?;
        let mut identity = [0; 5];
        for (destination, source) in identity.iter_mut().zip(values) {
            *destination = source
                .as_u64()
                .ok_or("Invalid executable mapping identity.")?;
        }
        if identity[2] == 0 || identity[2] > 256 * 1024 * 1024 || identity[4] & 0o170000 != 0o100000
        {
            return Err("Invalid executable mapping type or size.");
        }
        let digest = fields["sha256"]
            .as_str()
            .filter(|v| {
                v.len() == 64
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or("Invalid executable mapping hash.")?;
        let aliases = fields["targets"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .ok_or("Invalid executable mapping aliases.")?;
        let aliases = aliases
            .iter()
            .map(|v| path(v.as_str().ok_or("Invalid executable mapping path.")?))
            .collect::<Result<Vec<_>>>()?;
        if !aliases.contains(&image) || aliases.iter().any(|v| !targets.insert(v.clone())) {
            return Err("Ambiguous executable mapping aliases.");
        }
        total = total
            .checked_add(identity[2])
            .ok_or("Executable mapping budget exceeded.")?;
        if total > 1024 * 1024 * 1024 || targets.len() > 4096 {
            return Err("Executable mapping budget exceeded.");
        }
        result.push(Record {
            path: image,
            identity,
            digest: digest.to_owned(),
            aliases,
        });
    }
    Ok(result)
}
