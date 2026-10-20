//! Integrity-bound maintainer reuse. The caller must authenticate the root;
//! hashes or successful structural checks alone never authorize executable data.
use super::{catalog, json, objects, ObjectRef};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct PackReleaseReuse<F> {
    index: ObjectRef,
    count: usize,
    fetch: F,
}

impl<F: FnMut(&str) -> Result<Vec<u8>, &'static str>> PackReleaseReuse<F> {
    /// Verify the exact root bytes against a digest supplied by the caller's
    /// authenticated publication, independently of the untrusted cache path.
    pub fn from_bytes(bytes: &[u8], expected: &str, fetch: F) -> Result<Self, &'static str> {
        if bytes.is_empty()
            || bytes.len() > objects::OBJECT_BYTES
            || hex::encode(Sha256::digest(bytes)) != expected
        {
            return Err("command_pack_reuse_root_invalid");
        }
        Self::new(&json::decode(bytes)?, fetch)
    }
    /// `root` must come from the caller's authenticated release, never a cache
    /// file's own claim of authenticity. Different engines cannot seed reuse.
    pub fn new(root: &Value, fetch: F) -> Result<Self, &'static str> {
        if root["schema"] != "guard.command-pack-release.v1"
            || root["engine"] != env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION")
        {
            return Err("command_pack_reuse_engine_invalid");
        }
        let count = root["extensions"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("command_pack_reuse_root_invalid")?;
        let index = serde_json::from_value(root["index"].clone())
            .map_err(|_| "command_pack_reuse_root_invalid")?;
        Ok(Self {
            index,
            count,
            fetch,
        })
    }

    fn value(&mut self, reference: &Value) -> Result<Value, &'static str> {
        let reference: ObjectRef = serde_json::from_value(reference.clone())
            .map_err(|_| "command_pack_reuse_reference_invalid")?;
        json::decode_value(
            &objects::read_blob(&reference, &mut self.fetch)?,
            json::MAX_PROGRAM_OBJECT_MEMBERS,
        )
    }

    pub(super) fn get(
        &mut self,
        id: &str,
        key: &str,
    ) -> Result<Option<catalog::CompiledSourceCatalog>, &'static str> {
        self.read(id, Some(key))
    }

    pub(in crate::native_command_program) fn read(
        &mut self,
        id: &str,
        key: Option<&str>,
    ) -> Result<Option<catalog::CompiledSourceCatalog>, &'static str> {
        let Some(reference) = objects::lookup(&self.index, self.count, id, &mut self.fetch)? else {
            return Ok(None);
        };
        let manifest = json::decode(&objects::read_blob(&reference, &mut self.fetch)?)?;
        if manifest["schema"] != "guard.command-policy-pack.v1"
            || manifest["extension_id"] != id
            || manifest["engine"] != env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION")
            || manifest["semantic_profile"] != "cpython-3.12-ucd15"
        {
            return Err("command_pack_reuse_manifest_invalid");
        }
        // This key is recomputed from current strictly decoded sources, trust,
        // related interfaces, engine and semantic profile before lookup.
        if key.is_some_and(|key| manifest["cache_key"] != key) {
            return Ok(None);
        }
        let mut program = self.value(&manifest["program"])?;
        let Value::Object(references) = program
            .as_object_mut()
            .ok_or("command_pack_reuse_nodes_invalid")?
            .remove("nodes")
            .ok_or("command_pack_reuse_nodes_invalid")?
        else {
            return Err("command_pack_reuse_nodes_invalid");
        };
        if references.len() > 16384 {
            return Err("command_pack_reuse_nodes_invalid");
        }
        program["nodes"] = serde_json::json!({});
        let mut retained = serde_json::to_vec(&program)
            .map_err(|_| "command_pack_encoding_failed")?
            .len();
        for (index, (identity, reference)) in references.into_iter().enumerate() {
            let node = self.value(&reference)?;
            // Charge the assembled JSON, replacing rather than also charging
            // its storage references. Valid near-limit programs keep the same
            // byte budget as cold compilation.
            let key_bytes = serde_json::to_vec(&identity)
                .map_err(|_| "command_pack_encoding_failed")?
                .len();
            retained = retained
                .checked_add(
                    serde_json::to_vec(&node)
                        .map_err(|_| "command_pack_encoding_failed")?
                        .len(),
                )
                .and_then(|size| size.checked_add(key_bytes + 1 + usize::from(index > 0)))
                .filter(|size| *size <= objects::BLOB_BYTES)
                .ok_or("command_pack_reuse_nodes_invalid")?;
            program["nodes"][identity] = node;
        }
        if program["program_digest"] != manifest["program_digest"]
            || program["trust_digest"] != manifest["trust_digest"]
        {
            return Err("command_pack_reuse_program_invalid");
        }
        let catalog = self.value(&manifest["catalog"])?;
        let bytes = super::super::super::canonical_json_bytes(&catalog)
            .map_err(|_| "command_pack_encoding_failed")?;
        if program["catalog_digest"].as_str() != Some(hex::encode(Sha256::digest(bytes)).as_str()) {
            return Err("command_pack_reuse_catalog_invalid");
        }
        let descriptors = self
            .value(&manifest["descriptors"])?
            .as_array()
            .ok_or("command_pack_reuse_descriptors_invalid")?
            .clone();
        let source_digest = manifest["source_digest"]
            .as_str()
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            .ok_or("command_pack_reuse_manifest_invalid")?
            .to_owned();
        Ok(Some(catalog::CompiledSourceCatalog {
            catalog,
            descriptors,
            program,
            source_digest,
            implementation_digest: env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION").to_owned(),
            catalog_projection_kind: "complete".to_owned(),
            base_program_digest: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::collections::BTreeMap;

    #[test]
    fn malformed_program_shapes_return_an_error_without_panicking() {
        for program in [
            serde_json::json!([]),
            Value::Null,
            serde_json::json!({"nodes":[]}),
        ] {
            let mut bytes = Vec::new();
            let mut writer = objects::ObjectWriter::new(&mut bytes);
            let reference = writer.json(&program).unwrap();
            let manifest = writer.json(&serde_json::json!({
                "schema":"guard.command-policy-pack.v1", "extension_id":"command.one",
                "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"),
                "semantic_profile":"cpython-3.12-ucd15", "cache_key":"unit-key", "program":reference,
            })).unwrap();
            let index = writer
                .index(&[("command.one".to_owned(), manifest)])
                .unwrap();
            let root = serde_json::json!({"schema":"guard.command-pack-release.v1",
                "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"), "extensions":1, "index":index});
            let objects: BTreeMap<String, Vec<u8>> = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let row: Value = serde_json::from_slice(line).unwrap();
                    (
                        row["sha256"].as_str().unwrap().to_owned(),
                        STANDARD.decode(row["data"].as_str().unwrap()).unwrap(),
                    )
                })
                .collect();
            let mut reuse =
                PackReleaseReuse::new(&root, |id: &str| objects.get(id).cloned().ok_or("missing"))
                    .unwrap();
            assert_eq!(
                reuse.get("command.one", "unit-key").unwrap_err(),
                "command_pack_reuse_nodes_invalid"
            );
        }
    }
}
