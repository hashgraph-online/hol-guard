//! Complete bounded traversal of release interfaces. Transport locations are
//! byte retrieval hints, never installation or publisher authority.
use super::*;
use sha2::{Digest, Sha256};

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

pub(super) fn location_valid(value: &Value, sha: &str, kind: &str) -> bool {
    static TAG: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static CONTAINER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let tag = TAG.get_or_init(|| {
        regex::Regex::new(r"\Aextension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}\z")
            .unwrap()
    });
    let container =
        CONTAINER.get_or_init(|| regex::Regex::new(r"\A(objects|packs)-[0-9]{6}\.zip\z").unwrap());
    let suffix = if kind == "object" { ".json" } else { ".zip" };
    let member = format!("{kind}-{sha}{suffix}");
    if !value["tag"].as_str().is_some_and(|v| tag.is_match(v)) {
        return false;
    }
    if value.get("member").is_none() {
        keys(value, &["tag", "asset"]) && value["asset"] == member
    } else {
        keys(value, &["tag", "asset", "member"])
            && value["member"] == member
            && value["asset"].as_str().is_some_and(|v| {
                container.is_match(v)
                    && v.starts_with(if kind == "object" {
                        "objects-"
                    } else {
                        "packs-"
                    })
            })
    }
}

fn record_valid(record: &Value) -> bool {
    if !keys(
        record,
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
    ) {
        return false;
    }
    for field in ["dependencies", "related_interfaces"] {
        let Some(values) = record[field].as_array() else {
            return false;
        };
        let mut seen = BTreeSet::new();
        if values.iter().any(|v| {
            v.as_str().is_none_or(|id| {
                id.is_empty() || id.len() > 256 || !id.is_ascii() || !seen.insert(id)
            })
        }) {
            return false;
        }
    }
    let Some(archives) = record["archives"].as_array() else {
        return false;
    };
    if archives.is_empty() || archives.len() > 64 {
        return false;
    }
    let mut seen = BTreeSet::new();
    archives.iter().all(|archive| {
        keys(archive, &["sha256", "length", "location"])
            && archive["sha256"].as_str().is_some_and(|sha| {
                sha.len() == 64
                    && sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && seen.insert(sha)
            })
            && archive["length"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 32 * 1024 * 1024)
            && location_valid(
                &archive["location"],
                archive["sha256"].as_str().unwrap_or(""),
                "pack",
            )
    })
}

pub(super) fn inventory<R: BufRead, W: Write>(
    input: &Value,
    io: &mut Exchange<R, W>,
) -> Result<(Vec<Value>, BTreeMap<String, Value>), &'static str> {
    let root = &input["root"];
    let count = root["extensions"]
        .as_u64()
        .ok_or("authoring_root_invalid")? as usize;
    if root["schema"] != "guard.command-pack-release.v1"
        || root["engine"] != env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION")
        || count == 0
        || count > 100_000
    {
        return Err("authoring_root_invalid");
    }
    let installed = match input["mode"].as_str() {
        Some("installed") => true,
        Some("development") => false,
        _ => return Err("authoring_mode_invalid"),
    };
    let mut pending = vec![(
        root["index"].clone(),
        input["transport"].clone(),
        count,
        String::new(),
    )];
    let mut seen = BTreeSet::new();
    let mut manifests = BTreeMap::new();
    let mut catalog = Vec::new();
    let mut total_bytes = 0usize;
    while let Some((reference, transport, count, prefix)) = pending.pop() {
        if !seen.insert(reference["sha256"].clone().to_string())
            || seen.len() > 100_000
            || prefix.len() > 64
        {
            return Err("authoring_index_reference_invalid");
        }
        let wrapper = if installed {
            io.value(&transport)?
        } else {
            Value::Null
        };
        let page = if installed {
            let native = &wrapper["native"];
            let mut unlocated = native.clone();
            unlocated
                .as_object_mut()
                .ok_or("authoring_transport_invalid")?
                .remove("location");
            if unlocated != reference || wrapper["schema"] != "guard.policy-transport.v2" {
                return Err("authoring_transport_invalid");
            }
            io.value(native)?
        } else {
            io.value(&reference)?
        };
        if page["schema"] != "guard.pack-index.v1"
            || !keys(
                &page,
                &[
                    "schema",
                    "kind",
                    "prefix",
                    if page["kind"] == "leaf" {
                        "entries"
                    } else {
                        "children"
                    },
                ],
            )
            || page["prefix"] != prefix
            || reference["kind"] != "data"
            || reference["expanded_length"]
                .as_u64()
                .is_none_or(|n| n > 65536)
        {
            return Err("authoring_index_invalid");
        }
        if installed
            && (wrapper["kind"] != page["kind"]
                || !keys(
                    &wrapper,
                    &[
                        "schema",
                        "kind",
                        "native",
                        if page["kind"] == "leaf" {
                            "records"
                        } else {
                            "children"
                        },
                    ],
                ))
        {
            return Err("authoring_transport_invalid");
        }
        if page["kind"] == "leaf" {
            let entries = page["entries"]
                .as_array()
                .ok_or("authoring_index_invalid")?;
            if entries.len() != count || entries.is_empty() || entries.len() > 64 {
                return Err("authoring_index_count_invalid");
            }
            let records = if installed {
                Some(
                    wrapper["records"]
                        .as_array()
                        .ok_or("authoring_transport_invalid")?,
                )
            } else {
                None
            };
            if records.is_some_and(|r| r.len() != entries.len()) {
                return Err("authoring_transport_invalid");
            }
            let mut previous = String::new();
            for (position, row) in entries.iter().enumerate() {
                let id = row[0].as_str().ok_or("authoring_index_invalid")?;
                if row.as_array().is_none_or(|r| r.len() != 2)
                    || id.is_empty()
                    || id.len() > 256
                    || !id.is_ascii()
                    || id <= previous.as_str()
                    || !hex::encode(Sha256::digest(id.as_bytes())).starts_with(&prefix)
                {
                    return Err("authoring_index_invalid");
                }
                previous = id.to_owned();
                let (manifest, entries) = if let Some(records) = records {
                    let record_row = &records[position];
                    if record_row[0] != id || record_row.as_array().is_none_or(|r| r.len() != 2) {
                        return Err("authoring_transport_invalid");
                    }
                    let record = io.value(&record_row[1])?;
                    if !record_valid(&record)
                        || record["schema"] != "guard.policy-delivery.v2"
                        || record["extension_id"] != id
                        || record["manifest"] != row[1]
                        || !matches!(record["activation"].as_str(), Some("opt-in" | "default-on"))
                        || !matches!(
                            record["trust_class"].as_str(),
                            Some("external" | "first-party" | "trusted-library")
                        )
                        || !record["required"].is_boolean()
                    {
                        return Err("authoring_policy_record_invalid");
                    }
                    let entries = io.value(&record["catalog_metadata"])?;
                    (record, entries)
                } else {
                    let manifest = io.value(&row[1])?;
                    let entries = io.value(&manifest["catalog"])?;
                    (manifest, entries)
                };
                let entries = entries.as_array().ok_or("authoring_catalog_invalid")?;
                if entries.len() != 1
                    || entries[0]["extension_id"] != id
                    || manifests.insert(id.to_owned(), manifest).is_some()
                {
                    return Err("authoring_catalog_identity_invalid");
                }
                total_bytes += serde_json::to_vec(&entries[0])
                    .map_err(|_| "authoring_catalog_invalid")?
                    .len();
                if total_bytes > 128 * 1024 * 1024 || catalog.len() >= 100_000 {
                    return Err("authoring_catalog_byte_budget_exceeded");
                }
                catalog.push(entries[0].clone());
            }
        } else if page["kind"] == "branch" {
            let children = page["children"]
                .as_array()
                .ok_or("authoring_index_invalid")?;
            if children.is_empty() || children.len() > 16 || prefix.len() >= 64 {
                return Err("authoring_index_invalid");
            }
            let transports = if installed {
                Some(
                    wrapper["children"]
                        .as_array()
                        .ok_or("authoring_transport_invalid")?,
                )
            } else {
                None
            };
            if transports.is_some_and(|v| v.len() != children.len()) {
                return Err("authoring_transport_invalid");
            }
            let mut sum = 0usize;
            let mut previous = String::new();
            for (position, child) in children.iter().enumerate() {
                let key = child[0].as_str().ok_or("authoring_index_invalid")?;
                let n = child[1]
                    .as_u64()
                    .filter(|v| *v > 0 && *v <= 100_000)
                    .ok_or("authoring_index_invalid")? as usize;
                if child.as_array().is_none_or(|v| v.len() != 3)
                    || key.len() != prefix.len() + 1
                    || !key.starts_with(&prefix)
                    || key <= previous.as_str()
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("authoring_index_invalid");
                }
                previous = key.to_owned();
                sum += n;
                let transport = if let Some(transports) = transports {
                    let row = &transports[position];
                    if row[0] != child[0]
                        || row[1] != child[1]
                        || row.as_array().is_none_or(|v| v.len() != 3)
                    {
                        return Err("authoring_transport_invalid");
                    }
                    row[2].clone()
                } else {
                    Value::Null
                };
                pending.push((child[2].clone(), transport, n, key.to_owned()));
            }
            if sum != count {
                return Err("authoring_index_count_invalid");
            }
        } else {
            return Err("authoring_index_invalid");
        }
    }
    if catalog.len() != count {
        return Err("authoring_inventory_incomplete");
    }
    Ok((catalog, manifests))
}
