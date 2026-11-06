//! Bounded immutable build objects. Hashes establish integrity, never authority.
//! Runtime callers must obtain the root from an authenticated release binding.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

pub const OBJECT_BYTES: usize = 64 * 1024;
pub const FANOUT: usize = 64;
pub const BLOB_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub sha256: String,
    pub length: usize,
    pub expanded_length: usize,
    pub kind: String,
}

pub struct ObjectWriter<W> {
    output: W,
    seen: BTreeSet<String>,
    pub objects: usize,
    pub bytes: usize,
}

impl<W: Write> ObjectWriter<W> {
    pub fn new(output: W) -> Self {
        Self {
            output,
            seen: BTreeSet::new(),
            objects: 0,
            bytes: 0,
        }
    }

    fn object(
        &mut self,
        bytes: &[u8],
        kind: &str,
        expanded_length: usize,
    ) -> Result<ObjectRef, &'static str> {
        if bytes.is_empty() || bytes.len() > OBJECT_BYTES || expanded_length > BLOB_BYTES {
            return Err("command_pack_object_bounds_invalid");
        }
        let sha256 = hex::encode(Sha256::digest(bytes));
        if self.seen.insert(sha256.clone()) {
            let row = json!({"kind":"object", "sha256":sha256, "length":bytes.len(), "data":STANDARD.encode(bytes)});
            serde_json::to_writer(&mut self.output, &row)
                .map_err(|_| "command_pack_output_failed")?;
            self.output
                .write_all(b"\n")
                .map_err(|_| "command_pack_output_failed")?;
            self.objects += 1;
            self.bytes += bytes.len();
        }
        Ok(ObjectRef {
            sha256,
            length: bytes.len(),
            expanded_length,
            kind: kind.to_owned(),
        })
    }

    pub fn json(&mut self, value: &Value) -> Result<ObjectRef, &'static str> {
        let bytes = serde_json::to_vec(value).map_err(|_| "command_pack_encoding_failed")?;
        if bytes.len() > BLOB_BYTES {
            return Err("command_pack_blob_bounds_invalid");
        }
        if bytes.len() <= OBJECT_BYTES {
            return self.object(&bytes, "data", bytes.len());
        }
        let mut refs = bytes
            .chunks(OBJECT_BYTES)
            .map(|part| self.object(part, "data", part.len()))
            .collect::<Result<Vec<_>, _>>()?;
        while refs.len() > 1 {
            refs = refs
                .chunks(FANOUT)
                .map(|parts| {
                    let expanded_length = parts.iter().map(|part| part.expanded_length).sum();
                    // A reader admits a concatenation only when its bytes are
                    // the canonical encoding of what they parse to, so sort the
                    // keys here instead of relying on serde_json's selected Map
                    // implementation.
                    let bytes = crate::native_command_program::canonical_json_bytes(
                        &json!({"schema":"guard.pack-concat.v1", "parts":parts}),
                    )
                    .map_err(|_| "command_pack_encoding_failed")?;
                    self.object(&bytes, "concat", expanded_length)
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        Ok(refs.remove(0))
    }

    // A hash trie avoids shifting every following page when a source is added.
    // Every branch has at most 16 children and every leaf at most 64 entries.
    pub fn index(&mut self, entries: &[(String, ObjectRef)]) -> Result<ObjectRef, &'static str> {
        if entries.is_empty() || entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err("command_pack_index_order_invalid");
        }
        self.index_page(entries, "")
    }

    fn index_page(
        &mut self,
        entries: &[(String, ObjectRef)],
        prefix: &str,
    ) -> Result<ObjectRef, &'static str> {
        if entries.len() <= FANOUT {
            return self.json(&json!({"schema":"guard.pack-index.v1", "kind":"leaf", "prefix":prefix, "entries":entries}));
        }
        if prefix.len() >= 64 {
            return Err("command_pack_index_hash_collision");
        }
        let mut groups = BTreeMap::<String, Vec<(String, ObjectRef)>>::new();
        for entry in entries {
            let hash = hex::encode(Sha256::digest(entry.0.as_bytes()));
            groups
                .entry(hash[..prefix.len() + 1].to_owned())
                .or_default()
                .push(entry.clone());
        }
        let children = groups
            .into_iter()
            .map(|(prefix, entries)| {
                let reference = self.index_page(&entries, &prefix)?;
                Ok((prefix, entries.len(), reference))
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        self.json(&json!({"schema":"guard.pack-index.v1", "kind":"branch", "prefix":prefix, "children":children}))
    }
}

#[path = "native_command_pack_index.rs"]
mod index;
pub use index::lookup;

/// Offline verification helper. The caller supplies an already trusted root.
/// Fetch is local or controlled by an updater, never invoked during a decision.
pub fn read_blob(
    reference: &ObjectRef,
    fetch: &mut impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
) -> Result<Vec<u8>, &'static str> {
    fn read(
        reference: &ObjectRef,
        fetch: &mut impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
        depth: usize,
    ) -> Result<Vec<u8>, &'static str> {
        if depth > 4
            || reference.length == 0
            || reference.length > OBJECT_BYTES
            || reference.expanded_length == 0
            || reference.expanded_length > BLOB_BYTES
            || reference.sha256.len() != 64
            || !reference
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !matches!(reference.kind.as_str(), "data" | "concat")
        {
            return Err("command_pack_object_bounds_invalid");
        }
        let bytes = fetch(&reference.sha256)?;
        if bytes.len() != reference.length
            || hex::encode(Sha256::digest(&bytes)) != reference.sha256
        {
            return Err("command_pack_object_integrity_invalid");
        }
        match reference.kind.as_str() {
            "data" if bytes.len() == reference.expanded_length => Ok(bytes),
            "concat" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Concat {
                    schema: String,
                    parts: Vec<ObjectRef>,
                }
                let value: Concat =
                    serde_json::from_slice(&bytes).map_err(|_| "command_pack_concat_invalid")?;
                if value.schema != "guard.pack-concat.v1"
                    || value.parts.is_empty()
                    || value.parts.len() > FANOUT
                {
                    return Err("command_pack_concat_invalid");
                }
                let length = value
                    .parts
                    .iter()
                    .try_fold(0usize, |sum, part| sum.checked_add(part.expanded_length))
                    .ok_or("command_pack_blob_bounds_invalid")?;
                if length != reference.expanded_length {
                    return Err("command_pack_concat_invalid");
                }
                let mut result = Vec::with_capacity(length);
                for part in value.parts {
                    result.extend(read(&part, fetch, depth + 1)?);
                }
                Ok(result)
            }
            _ => Err("command_pack_object_kind_invalid"),
        }
    }
    read(reference, fetch, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn fixed_object_budgets_match_the_format_contract() {
        let limits: Value = serde_json::from_str(include_str!(
            "../../../../contracts/catalog-delivery/packs.v1.json"
        ))
        .unwrap();
        assert_eq!(limits["max_object_bytes"], OBJECT_BYTES);
        assert_eq!(limits["max_blob_bytes"], BLOB_BYTES);
        assert_eq!(limits["concat_fanout"], FANOUT);
        assert_eq!(limits["index_leaf_entries"], FANOUT);
    }

    /// Every object the writer emitted, keyed by digest.
    fn written(output: &[u8]) -> BTreeMap<String, Vec<u8>> {
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let row: Value = serde_json::from_slice(line).unwrap();
                (
                    row["sha256"].as_str().unwrap().to_owned(),
                    STANDARD.decode(row["data"].as_str().unwrap()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn concatenations_are_written_canonically() {
        // A reader admits a concatenation only when its bytes are the canonical
        // encoding of what they parse to. Key order in `json!` and in a derived
        // struct follows serde_json's selected Map implementation, which a build
        // dependency may switch to insertion order, so the writer sorts instead.
        let mut output = Vec::new();
        let mut writer = ObjectWriter::new(&mut output);
        writer
            .json(&json!({"text":"a".repeat(OBJECT_BYTES * 3 + 7)}))
            .unwrap();
        let concatenations: Vec<Vec<u8>> = written(&output)
            .into_values()
            .filter(|bytes| {
                serde_json::from_slice::<Value>(bytes)
                    .map(|value| value["schema"] == "guard.pack-concat.v1")
                    .unwrap_or(false)
            })
            .collect();
        assert!(!concatenations.is_empty());
        for bytes in concatenations {
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                bytes,
                crate::native_command_program::canonical_json_bytes(&value).unwrap()
            );
        }
    }

    #[test]
    fn chunks_are_bounded_complete_and_authenticated() {
        let mut output = Vec::new();
        let mut writer = ObjectWriter::new(&mut output);
        let value = json!({"text":"a".repeat(OBJECT_BYTES * 3 + 7)});
        let reference = writer.json(&value).unwrap();
        let mut objects = written(&output);
        assert!(objects.values().all(|bytes| bytes.len() <= OBJECT_BYTES));
        assert_eq!(
            read_blob(&reference, &mut |id| objects
                .get(id)
                .cloned()
                .ok_or("missing"))
            .unwrap(),
            serde_json::to_vec(&value).unwrap()
        );
        objects.get_mut(&reference.sha256).unwrap()[0] ^= 1;
        assert_eq!(
            read_blob(&reference, &mut |id| objects
                .get(id)
                .cloned()
                .ok_or("missing"))
            .unwrap_err(),
            "command_pack_object_integrity_invalid"
        );
    }

    #[test]
    fn forged_lengths_missing_parts_and_excessive_expansion_fail_closed() {
        let reference = ObjectRef {
            sha256: "0".repeat(64),
            length: OBJECT_BYTES + 1,
            expanded_length: 1,
            kind: "data".into(),
        };
        assert_eq!(
            read_blob(&reference, &mut |_| panic!(
                "invalid lengths must fail before fetch"
            ))
            .unwrap_err(),
            "command_pack_object_bounds_invalid"
        );
        let mut output = Vec::new();
        let mut writer = ObjectWriter::new(&mut output);
        let reference = writer
            .json(&json!({"text":"b".repeat(OBJECT_BYTES + 5)}))
            .unwrap();
        assert_eq!(
            read_blob(&reference, &mut |_| Err("missing")).unwrap_err(),
            "missing"
        );
        let mut forged = reference.clone();
        forged.expanded_length = BLOB_BYTES + 1;
        assert_eq!(
            read_blob(&forged, &mut |_| panic!("do not fetch oversized content")).unwrap_err(),
            "command_pack_object_bounds_invalid"
        );
        let mut objects = written(&output);
        let row: Value = serde_json::from_slice(objects.get(&reference.sha256).unwrap()).unwrap();
        let missing = row["parts"][0]["sha256"].as_str().unwrap();
        objects.remove(missing);
        assert_eq!(
            read_blob(&reference, &mut |id| objects
                .get(id)
                .cloned()
                .ok_or("missing"))
            .unwrap_err(),
            "missing"
        );
    }

    #[test]
    fn lookup_reads_one_path_and_addition_preserves_other_pages() {
        let mut output = Vec::new();
        let mut writer = ObjectWriter::new(&mut output);
        let item = writer.json(&json!({"policy":"placeholder"})).unwrap();
        let mut entries: Vec<_> = (0..500)
            .map(|index| (format!("command.example-{index:04}"), item.clone()))
            .collect();
        let root = writer.index(&entries).unwrap();
        let before = writer.objects;
        entries.push(("command.extra".into(), item.clone()));
        let next = writer.index(&entries).unwrap();
        assert_ne!(root, next);
        assert!(
            writer.objects - before <= 3,
            "unrelated pages must remain immutable"
        );
        let objects = written(&output);
        let mut reads = 0;
        let found = lookup(&next, entries.len(), "command.example-0250", &mut |id| {
            reads += 1;
            objects.get(id).cloned().ok_or("missing")
        })
        .unwrap();
        assert_eq!(found, Some(item));
        assert!(reads <= 3);
        assert!(lookup(
            &next,
            entries.len() - 1,
            "command.example-0250",
            &mut |id| objects.get(id).cloned().ok_or("missing")
        )
        .is_err());
    }
}
