//! Located transport proofs, validated without fetching policy archives.
use super::io::{self, Result, BLOB_BYTES, OBJECT_BYTES};
use crate::native_command_program::source::{read_pack_blob, PackObjectRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Located {
    pub sha256: String,
    pub length: usize,
    pub expanded_length: usize,
    pub kind: String,
    pub location: Location,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Location {
    tag: String,
    asset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    member: Option<String>,
}

pub(super) fn location(value: &Location, digest: &str, kind: &str, source: &str) -> Result<()> {
    let suffix = if kind == "object" { ".json" } else { ".zip" };
    let expected = format!("{kind}-{digest}{suffix}");
    use std::sync::OnceLock;
    static TAG: OnceLock<regex::Regex> = OnceLock::new();
    static ARCHIVE: OnceLock<regex::Regex> = OnceLock::new();
    let tag = TAG.get_or_init(|| {
        regex::Regex::new(r"^extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}$")
            .unwrap()
    });
    let archive =
        ARCHIVE.get_or_init(|| regex::Regex::new(r"^(objects|packs)-[0-9]{6}\.zip$").unwrap());
    if !tag.is_match(&value.tag)
        || (!source.is_empty()
            && !value
                .tag
                .starts_with(&format!("extension-data-{source}-0.0-")))
        || match &value.member {
            None => value.asset != expected,
            Some(member) => {
                member != &expected
                    || !archive.is_match(&value.asset)
                    || !value.asset.starts_with(if kind == "object" {
                        "objects-"
                    } else {
                        "packs-"
                    })
            }
        }
    {
        return Err("catalog_prepare_location_invalid");
    }
    Ok(())
}

pub(super) fn reference(value: &Value) -> Result<PackObjectRef> {
    let reference: PackObjectRef =
        serde_json::from_value(value.clone()).map_err(|_| "catalog_prepare_reference_invalid")?;
    if reference.sha256.len() != 64
        || !reference
            .sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || reference.length == 0
        || reference.length > OBJECT_BYTES
        || reference.expanded_length == 0
        || reference.expanded_length > BLOB_BYTES
        || !matches!(reference.kind.as_str(), "data" | "concat")
        || (reference.kind == "data" && reference.length != reference.expanded_length)
    {
        return Err("catalog_prepare_reference_invalid");
    }
    Ok(reference)
}

impl Located {
    pub fn raw(&self) -> PackObjectRef {
        PackObjectRef {
            sha256: self.sha256.clone(),
            length: self.length,
            expanded_length: self.expanded_length,
            kind: self.kind.clone(),
        }
    }
    pub fn validate(&self, source: &str) -> Result<()> {
        reference(
            &serde_json::to_value(self.raw()).map_err(|_| "catalog_prepare_reference_invalid")?,
        )?;
        location(&self.location, &self.sha256, "object", source)
    }
}

pub(super) enum LoadError {
    Missing(Box<Located>),
    Invalid(&'static str),
}
impl From<&'static str> for LoadError {
    fn from(value: &'static str) -> Self {
        Self::Invalid(value)
    }
}

pub(super) fn load(
    directory: &super::CacheReader,
    reference: &Located,
    source: &str,
    depth: usize,
    fetched: &std::collections::BTreeMap<String, Vec<u8>>,
) -> std::result::Result<Vec<u8>, LoadError> {
    reference.validate(source)?;
    if depth > 4 {
        return Err("catalog_prepare_concat_depth".into());
    }
    // Reuse only the current bounded, integrity-checked advance batch. Cached
    // on-disk objects always use private-path and stable-read validation.
    let data = match fetched
        .get(&reference.sha256)
        .map(|bytes| Ok(bytes.clone()))
        .unwrap_or_else(|| directory.read(&reference.sha256))
    {
        // A damaged rebuildable cache is fetched again, never consumed. The
        // advance path checks the expected SHA/length before atomic repair.
        Err("catalog_prepare_object_corrupt" | "catalog_prepare_object_missing") => {
            return Err(LoadError::Missing(Box::new(reference.clone())))
        }
        result => result?,
    };
    // Reuse the native pack verifier for every raw immutable object.
    let raw = PackObjectRef {
        kind: "data".into(),
        expanded_length: reference.length,
        ..reference.raw()
    };
    let data = read_pack_blob(&raw, &mut |_| Ok(data.clone()))?;
    if reference.kind == "data" {
        return Ok(data);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Concat {
        schema: String,
        parts: Vec<Located>,
    }
    let value: Concat =
        serde_json::from_value(io::json(&data)?).map_err(|_| "catalog_prepare_concat_invalid")?;
    let total = value
        .parts
        .iter()
        .try_fold(0usize, |sum, p| sum.checked_add(p.expanded_length));
    if value.schema != "guard.delivery-concat.v2"
        || value.parts.is_empty()
        || value.parts.len() > 64
        || total != Some(reference.expanded_length)
    {
        return Err("catalog_prepare_concat_invalid".into());
    }
    let mut bytes = Vec::with_capacity(reference.expanded_length);
    for part in value.parts {
        bytes.extend(load(directory, &part, source, depth + 1, fetched)?);
    }
    Ok(bytes)
}

#[derive(Clone, Debug)]
pub(super) enum Job {
    Transport(Located, PackObjectRef, usize, String),
    Index(Located, Value, usize, String),
    Record(Located, String, PackObjectRef),
    Metadata(Located, String),
}
impl Job {
    pub fn target(&self) -> &Located {
        match self {
            Self::Transport(r, ..)
            | Self::Index(r, ..)
            | Self::Record(r, ..)
            | Self::Metadata(r, ..) => r,
        }
    }
}

pub(super) fn fields(value: &Value, names: &[&str]) -> Result<()> {
    if value
        .as_object()
        .is_none_or(|v| v.len() != names.len() || names.iter().any(|n| !v.contains_key(*n)))
    {
        return Err("catalog_prepare_fields_invalid");
    }
    Ok(())
}
pub(super) fn located(value: &Value, source: &str) -> Result<Located> {
    let result: Located =
        serde_json::from_value(value.clone()).map_err(|_| "catalog_prepare_reference_invalid")?;
    result.validate(source)?;
    Ok(result)
}

pub(super) fn transport(
    value: Value,
    expected: &PackObjectRef,
    count: usize,
    prefix: &str,
    source: &str,
) -> Result<Job> {
    let native = located(&value["native"], source)?;
    if value["schema"] != "guard.policy-transport.v2"
        || native.raw() != *expected
        || native.kind != "data"
        || count == 0
        || prefix.len() > 64
    {
        return Err("catalog_prepare_transport_invalid");
    }
    Ok(Job::Index(native, value, count, prefix.into()))
}

pub(super) fn index(
    value: &Value,
    wrapper: &Value,
    count: usize,
    prefix: &str,
    source: &str,
) -> Result<Vec<Job>> {
    let leaf = value["kind"] == "leaf";
    let rows_key = if leaf { "entries" } else { "children" };
    let wrappers_key = if leaf { "records" } else { "children" };
    fields(value, &["schema", "kind", "prefix", rows_key])?;
    fields(wrapper, &["schema", "kind", "native", wrappers_key])?;
    if value["schema"] != "guard.pack-index.v1"
        || value["prefix"] != prefix
        || wrapper["kind"] != value["kind"]
        || (!leaf && (value["kind"] != "branch" || prefix.len() >= 64))
    {
        return Err("catalog_prepare_index_invalid");
    }
    let rows = value[rows_key]
        .as_array()
        .ok_or("catalog_prepare_index_invalid")?;
    let wrappers = wrapper[wrappers_key]
        .as_array()
        .ok_or("catalog_prepare_transport_invalid")?;
    if rows.is_empty()
        || rows.len() > if leaf { 64 } else { 16 }
        || wrappers.len() != rows.len()
        || (leaf && rows.len() != count)
    {
        return Err("catalog_prepare_count_invalid");
    }
    let mut previous = "";
    let mut total = 0usize;
    let mut jobs = Vec::new();
    for (row, wrapped) in rows.iter().zip(wrappers) {
        let row = row.as_array().ok_or("catalog_prepare_index_invalid")?;
        let wrapped = wrapped
            .as_array()
            .ok_or("catalog_prepare_transport_invalid")?;
        let width = if leaf { 2 } else { 3 };
        if row.len() != width || wrapped.len() != width || row[..width - 1] != wrapped[..width - 1]
        {
            return Err("catalog_prepare_transport_incomplete");
        }
        let key = row[0].as_str().ok_or("catalog_prepare_index_invalid")?;
        if key <= previous {
            return Err("catalog_prepare_duplicate_identity");
        }
        previous = key;
        let raw = reference(&row[width - 1])?;
        let target = located(&wrapped[width - 1], source)?;
        if leaf {
            if key.is_empty()
                || key.len() > 256
                || !key.is_ascii()
                || !io::hash(key.as_bytes()).starts_with(prefix)
            {
                return Err("catalog_prepare_index_ownership");
            }
            jobs.push(Job::Record(target, key.into(), raw));
        } else {
            let n = row[1]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("catalog_prepare_count_invalid")?;
            if n == 0
                || key.len() != prefix.len() + 1
                || !key.starts_with(prefix)
                || !key
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err("catalog_prepare_index_ownership");
            }
            total = total
                .checked_add(n)
                .ok_or("catalog_prepare_count_invalid")?;
            if total > count {
                return Err("catalog_prepare_count_invalid");
            }
            jobs.push(Job::Transport(target, raw, n, key.into()));
        }
    }
    if !leaf && total != count {
        return Err("catalog_prepare_count_invalid");
    }
    Ok(jobs)
}

pub(super) fn record(
    value: &Value,
    id: &str,
    manifest: &PackObjectRef,
    source: &str,
) -> Result<Job> {
    fields(
        value,
        &[
            "schema",
            "extension_id",
            "manifest",
            "catalog_metadata",
            "archives",
            "dependencies",
            "related_interfaces",
            "required",
            "activation",
            "trust_class",
        ],
    )?;
    if value["schema"] != "guard.policy-delivery.v2"
        || value["extension_id"] != id
        || reference(&value["manifest"])? != *manifest
        || !value["required"].is_boolean()
        || !matches!(value["activation"].as_str(), Some("opt-in" | "default-on"))
        || !matches!(
            value["trust_class"].as_str(),
            Some("external" | "trusted-library" | "first-party")
        )
    {
        return Err("catalog_prepare_record_invalid");
    }
    for field in ["dependencies", "related_interfaces"] {
        let items = value[field]
            .as_array()
            .ok_or("catalog_prepare_record_invalid")?;
        let mut seen = std::collections::BTreeSet::new();
        for item in items {
            let id = item.as_str().ok_or("catalog_prepare_record_invalid")?;
            if id.is_empty() || id.len() > 256 || !id.is_ascii() || !seen.insert(id) {
                return Err("catalog_prepare_record_invalid");
            }
        }
    }
    let archives = value["archives"]
        .as_array()
        .ok_or("catalog_prepare_record_invalid")?;
    if archives.is_empty() || archives.len() > 64 {
        return Err("catalog_prepare_archive_invalid");
    }
    let mut seen = std::collections::BTreeSet::new();
    for archive in archives {
        fields(archive, &["sha256", "length", "location"])?;
        let digest = archive["sha256"]
            .as_str()
            .ok_or("catalog_prepare_archive_invalid")?;
        let length = archive["length"]
            .as_u64()
            .ok_or("catalog_prepare_archive_invalid")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || length == 0
            || length > 32 * 1024 * 1024
            || !seen.insert(digest)
        {
            return Err("catalog_prepare_archive_invalid");
        }
        let target: Location = serde_json::from_value(archive["location"].clone())
            .map_err(|_| "catalog_prepare_location_invalid")?;
        location(&target, digest, "pack", source)?;
    }
    Ok(Job::Metadata(
        located(&value["catalog_metadata"], source)?,
        id.into(),
    ))
}
