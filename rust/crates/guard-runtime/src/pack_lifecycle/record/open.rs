//! `activation_record.open_record` after authentication: the publication and
//! inventories an authenticated activation binds, read from the local delivery
//! cache only. Nothing is fetched; a missing object refuses the record.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    digest, has_exactly, int, int_in, location, matches, py_eq, reference, Result, MAX_BLOB_BYTES,
    MAX_EXECUTABLES, MAX_OBJECT_BYTES, MAX_RECORD_BYTES, MAX_SELECTED,
};

const REGISTRY_PAGE: &str = "guard.command-pack-registry-page.v1";
const EXECUTABLE_PAGE: &str = "guard.command-pack-executables-page.v1";
const SELECTION_PAGE: &str = "guard.command-pack-selection-page.v1";
const PUBLICATION_FIELDS: [&str; 6] = [
    "source_sha",
    "engine",
    "publication_id",
    "authority_epoch",
    "issued_at",
    "expires_at",
];
const PLAIN: [&str; 4] = ["sha256", "length", "expanded_length", "kind"];
const LOCATED: [&str; 5] = ["sha256", "length", "expanded_length", "kind", "location"];

/// Walks a document only to refuse a repeated object key; values are dropped.
/// It reads keys rather than values, so the workspace's arbitrary-precision
/// number tokens pass through it like any other single-entry map.
struct UniqueKeys;

impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueKeys)
    }
}

impl<'de> Visitor<'de> for UniqueKeys {
    type Value = UniqueKeys;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> std::result::Result<Self, E> {
        Ok(self)
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self, E> {
        Ok(self)
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self, E> {
        Ok(self)
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self, E> {
        Ok(self)
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<Self, E> {
        Ok(self)
    }
    fn visit_unit<E>(self) -> std::result::Result<Self, E> {
        Ok(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Self, A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(self)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Self, A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate field"));
            }
            map.next_value::<UniqueKeys>()?;
        }
        Ok(self)
    }
}

/// `pack_store.decode`: any JSON its writer stored, refusing a duplicated
/// field. A publication keeps the exact bytes its attestation signed, so the
/// reader cannot require them to be canonical.
fn decode(bytes: &[u8]) -> Result<Value> {
    let invalid = |_| "activation metadata object invalid".to_owned();
    serde_json::from_slice::<UniqueKeys>(bytes).map_err(invalid)?;
    serde_json::from_slice(bytes).map_err(invalid)
}

fn identity(value: &Value) -> bool {
    static IDENTITY: OnceLock<Regex> = OnceLock::new();
    value.as_str().is_some_and(|text| text.len() <= 256)
        && matches(&IDENTITY, r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$", value)
}

/// Strictly ascending strings, which is `values == sorted(set(values))`.
fn ascending(values: &[Value]) -> bool {
    values
        .windows(2)
        .all(|pair| matches!((pair[0].as_str(), pair[1].as_str()), (Some(a), Some(b)) if a < b))
}

struct Reader<'a> {
    objects: &'a Path,
}

impl Reader<'_> {
    /// `PackReader.blob` for plain references, `LocatedStore.blob` without a
    /// fetcher for located ones.
    fn blob(&self, value: &Value, depth: usize, located: bool) -> Result<Vec<u8>> {
        let invalid = || "activation metadata object invalid".to_owned();
        let map = value.as_object().ok_or_else(invalid)?;
        if depth > 4
            || !has_exactly(map, if located { &LOCATED[..] } else { &PLAIN[..] })
            || !digest(&map["sha256"])
            || !int_in(&map["length"], 1, MAX_OBJECT_BYTES)
            || !int_in(&map["expanded_length"], 1, MAX_BLOB_BYTES)
            || !matches!(map["kind"].as_str(), Some("data" | "concat"))
        {
            return Err(invalid());
        }
        let sha = map["sha256"].as_str().unwrap_or_default();
        if located {
            location(&map["location"], sha)?;
        }
        let length = int(&map["length"]).unwrap_or_default() as usize;
        let expanded = int(&map["expanded_length"]).unwrap_or_default() as usize;
        let path = self.objects.join(format!("{sha}.json"));
        let bytes = guard_secure_fs::read_bounded(&path, MAX_OBJECT_BYTES as usize)
            .map_err(|_| "activation metadata object unavailable")?
            .bytes;
        if bytes.len() != length || hex::encode(Sha256::digest(&bytes)) != sha {
            return Err("activation metadata object integrity invalid".into());
        }
        if map["kind"] == "data" {
            return if length == expanded {
                Ok(bytes)
            } else {
                Err(invalid())
            };
        }
        let concat = decode(&bytes)?;
        let schema = if located {
            "guard.delivery-concat.v2"
        } else {
            "guard.pack-concat.v1"
        };
        let parts = concat
            .as_object()
            .filter(|map| has_exactly(map, &["schema", "parts"]) && map["schema"] == schema)
            .and_then(|map| map["parts"].as_array())
            .filter(|parts| (1..=64).contains(&parts.len()))
            .ok_or_else(invalid)?;
        let mut output = Vec::with_capacity(expanded);
        let mut total = 0usize;
        for part in parts {
            // Check declared expansion before retaining any child data.
            let declared = part
                .as_object()
                .and_then(|part| part.get("expanded_length"))
                .and_then(int)
                .filter(|n| *n > 0)
                .ok_or_else(invalid)? as usize;
            total = total.checked_add(declared).ok_or_else(invalid)?;
            if total > expanded {
                return Err(invalid());
            }
            output.extend(self.blob(part, depth + 1, located)?);
        }
        if total != expanded || output.len() != expanded {
            return Err(invalid());
        }
        Ok(output)
    }

    fn json(&self, value: &Value, located: bool) -> Result<Value> {
        decode(&self.blob(value, 0, located)?)
    }

    /// `activation_record._items`: every entry of a bounded page chain.
    fn items(
        &self,
        first: &Value,
        count: &Value,
        schema: &str,
        maximum: i128,
        field: &str,
    ) -> Result<Vec<Value>> {
        if !int_in(count, 0, maximum) || first.is_null() != (int(count) == Some(0)) {
            return Err("activation metadata count invalid".into());
        }
        let count = int(count).unwrap_or_default() as usize;
        let mut seen = BTreeSet::new();
        let mut items = Vec::with_capacity(count);
        let mut next = first.clone();
        while !next.is_null() {
            reference(&next)?;
            if int(&next["expanded_length"]).unwrap_or_default() > MAX_RECORD_BYTES as i128
                || !seen.insert(next["sha256"].as_str().unwrap_or_default().to_owned())
            {
                return Err("activation metadata page bounds invalid".into());
            }
            let page = self.json(&next, false)?;
            let entries = page
                .as_object()
                .filter(|map| {
                    has_exactly(map, &["schema", field, "next"]) && map["schema"] == schema
                })
                .and_then(|map| map[field].as_array())
                .filter(|entries| (1..=64).contains(&entries.len()))
                .ok_or("activation metadata page invalid")?;
            for entry in entries {
                if items.len() == count {
                    return Err("activation metadata has surplus entries".into());
                }
                items.push(entry.clone());
            }
            next = page["next"].clone();
        }
        if items.len() != count {
            return Err("activation metadata is incomplete".into());
        }
        Ok(items)
    }
}

/// The inventories an authenticated activation header binds.
pub(super) fn open(value: &Value, directory: &Path) -> Result<Value> {
    let objects = directory.join("objects");
    let reader = Reader { objects: &objects };
    let distribution = &value["distribution"];
    if int(&distribution["expanded_length"]).unwrap_or_default() > MAX_RECORD_BYTES as i128
        || distribution["sha256"] != value["root_digest"]
    {
        return Err("activation distribution binding invalid".into());
    }
    let publication = reader.json(distribution, false)?;
    let schema = if value["issued_at"].is_null() {
        "guard.command-pack-bundle.v1"
    } else {
        "guard.extension-distribution.v2"
    };
    let publication = publication
        .as_object()
        .filter(|map| map.get("schema").is_some_and(|found| found == schema))
        .ok_or("activation publication identity invalid")?;
    let epoch = publication
        .get("policy")
        .and_then(|policy| policy.get("revocations"))
        .and_then(|revocations| revocations.get("epoch"))
        .ok_or("activation publication identity invalid")?;
    if PUBLICATION_FIELDS.iter().any(|name| {
        !py_eq(
            publication.get(*name).unwrap_or(&Value::Null),
            &value[*name],
        )
    }) || !py_eq(epoch, &value["revocation_epoch"])
    {
        return Err("activation publication identity invalid".into());
    }
    let selected = reader.items(
        &value["selection"],
        &value["selected_count"],
        SELECTION_PAGE,
        MAX_SELECTED,
        "ids",
    )?;
    if selected.is_empty() || !selected.iter().all(identity) || !ascending(&selected) {
        return Err("activation selected inventory invalid".into());
    }
    let registry = reader.items(
        &value["registry"],
        &value["registry_count"],
        REGISTRY_PAGE,
        MAX_SELECTED,
        "items",
    )?;
    let executables = reader.items(
        &value["executables"],
        &value["executable_count"],
        EXECUTABLE_PAGE,
        MAX_EXECUTABLES,
        "items",
    )?;
    if !executables.iter().all(|item| {
        item.as_str()
            .is_some_and(|text| (1..=8192).contains(&text.chars().count()))
    }) || !ascending(&executables)
    {
        return Err("activation executable inventory invalid".into());
    }
    let mut ids = Vec::with_capacity(registry.len());
    for item in &registry {
        let catalog = reader.json(item, true)?;
        let entry = catalog
            .as_array()
            .filter(|catalog| catalog.len() == 1)
            .and_then(|catalog| catalog[0].as_object())
            .ok_or("activation registry metadata invalid")?;
        ids.push(entry.get("extension_id").cloned().unwrap_or(Value::Null));
    }
    let known: BTreeSet<&str> = ids.iter().filter_map(Value::as_str).collect();
    if !ids.iter().all(identity)
        || !ascending(&ids)
        || !selected
            .iter()
            .all(|id| id.as_str().is_some_and(|id| known.contains(id)))
    {
        return Err("activation registry inventory invalid".into());
    }
    Ok(json!({
        "value": value,
        "selected": selected,
        "registry": registry,
        "registry_ids": ids,
        "executables": executables,
    }))
}

#[cfg(test)]
#[path = "open_tests.rs"]
mod tests;
