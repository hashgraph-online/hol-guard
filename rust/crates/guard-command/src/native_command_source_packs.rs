//! Offline pack compilation from unchanged sources. Only the release pack root
//! is published after every source and global relationship has been validated.

use super::{catalog, contract::SourceDocument, json, mcp, validation};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    sync::Arc,
};

#[path = "native_command_pack_objects.rs"]
pub mod objects;
use objects::{ObjectRef, ObjectWriter};
#[path = "native_command_source_pack_reuse.rs"]
mod reuse;
pub use reuse::PackReleaseReuse;

/// Only freshly compiled results or authenticated release inputs revalidated by
/// this instance enter its bounded cache. Cache contents grant no policy authority.
pub struct PackCompiler {
    cache: BTreeMap<String, (String, Arc<catalog::CompiledSourceCatalog>, usize)>,
    bytes: usize,
    limit: usize,
}

#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct CompilationStats {
    pub compiled: usize,
    pub reused: usize,
    pub retained_encoded_bytes: usize,
}

const CACHE_BYTES: usize = 64 * 1024 * 1024;

impl Default for PackCompiler {
    fn default() -> Self {
        Self {
            cache: BTreeMap::new(),
            bytes: 0,
            limit: CACHE_BYTES,
        }
    }
}

impl PackCompiler {
    pub fn compile(
        &mut self,
        reader: impl Read,
        output: impl Write,
    ) -> Result<(Value, CompilationStats), &'static str> {
        compile(reader, output, self, &mut |_, _| Ok(None))
    }

    /// Maintainer-only reuse from a root authenticated by the release caller.
    /// This does not install policy or grant the build output runtime authority.
    pub fn compile_reusing(
        &mut self,
        reader: impl Read,
        output: impl Write,
        reuse: &mut PackReleaseReuse<impl FnMut(&str) -> Result<Vec<u8>, &'static str>>,
    ) -> Result<(Value, CompilationStats), &'static str> {
        compile(reader, output, self, &mut |id, key| reuse.get(id, key))
    }
}

fn frame(reader: &mut impl Read) -> Result<Vec<u8>, &'static str> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| "command_pack_stream_truncated")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > super::MAX_SOURCE_INPUT_BYTES {
        return Err("command_source_bytes_invalid");
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "command_pack_stream_truncated")?;
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    kind: String,
    trust: Value,
}

struct Input {
    bytes: Vec<u8>,
    server: bool,
    trust: Value,
    fingerprint: String,
}

fn references(document: &SourceDocument, owners: &BTreeMap<&str, &str>) -> BTreeSet<String> {
    let extension = &document.extension;
    let mut refs: BTreeSet<_> = extension
        .dependencies
        .iter()
        .chain(&extension.conflicts)
        .cloned()
        .collect();
    for permission in &extension.permissions {
        for id in permission
            .dependencies
            .iter()
            .chain(&permission.implied_permissions)
            .chain(&permission.conflicts)
            .chain(permission.replacement_permission_id.iter())
        {
            // Global validation has already established every referenced owner.
            refs.insert(owners[id.as_str()].to_owned());
        }
    }
    refs
}

/// Emits bounded object records followed by one complete root record. This
/// compiler API grants no activation authority and accepts no filesystem paths.
/// An interrupted stream never emits a root and cannot replace a release.
pub fn compile_pack_stream(reader: impl Read, output: impl Write) -> Result<Value, &'static str> {
    PackCompiler {
        limit: 0,
        ..PackCompiler::default()
    }
    .compile(reader, output)
    .map(|(root, _)| root)
}

/// One-shot maintainer compilation with integrity-bound external reuse and no
/// retained IR cache. The caller remains responsible for root authentication.
pub fn compile_pack_stream_reusing(
    reader: impl Read,
    output: impl Write,
    reuse: &mut PackReleaseReuse<impl FnMut(&str) -> Result<Vec<u8>, &'static str>>,
) -> Result<(Value, CompilationStats), &'static str> {
    PackCompiler {
        limit: 0,
        ..PackCompiler::default()
    }
    .compile_reusing(reader, output, reuse)
}

fn compile(
    mut reader: impl Read,
    output: impl Write,
    compiler: &mut PackCompiler,
    reuse: &mut impl FnMut(&str, &str) -> Result<Option<catalog::CompiledSourceCatalog>, &'static str>,
) -> Result<(Value, CompilationStats), &'static str> {
    let mut magic = [0; 5];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "command_pack_stream_truncated")?;
    if &magic != b"HGPS\x01" {
        return Err("command_pack_stream_version_unsupported");
    }
    let header: Header = serde_json::from_value(json::decode(&frame(&mut reader)?)?)
        .map_err(|_| "command_pack_header_invalid")?;
    if header.schema != "guard.command-pack-source-stream.v1" || header.count == 0 {
        return Err("command_pack_header_invalid");
    }
    let mut documents = Vec::new();
    let mut inputs = BTreeMap::new();
    let mut publishers = None;
    for _ in 0..header.count {
        let metadata: Metadata = serde_json::from_value(json::decode(&frame(&mut reader)?)?)
            .map_err(|_| "command_pack_metadata_invalid")?;
        let server = match metadata.kind.as_str() {
            "command" => false,
            "mcp" => true,
            _ => return Err("command_pack_metadata_invalid"),
        };
        catalog::validate_trust(
            &serde_json::to_vec(&metadata.trust).map_err(|_| "command_pack_encoding_failed")?,
        )?;
        if publishers
            .as_ref()
            .is_some_and(|value| value != &metadata.trust["publishers"])
        {
            return Err("command_pack_publisher_conflict");
        }
        publishers = Some(metadata.trust["publishers"].clone());
        let bytes = frame(&mut reader)?;
        let value = json::decode(&bytes)?;
        let document: SourceDocument = if server {
            mcp::lower(&bytes)?.document
        } else {
            serde_json::from_value(value.clone()).map_err(|_| "command_source_contract_invalid")?
        };
        validation::validate(&document, server)?;
        let id = document.extension.extension_id.clone();
        let classes = metadata.trust["classes"]
            .as_object()
            .ok_or("command_pack_trust_binding_invalid")?;
        let bindings: Vec<_> = classes
            .values()
            .flat_map(|value| value.as_array().into_iter().flatten())
            .collect();
        if bindings.len() != 1 || bindings[0].as_str() != Some(&id) {
            return Err("command_pack_trust_binding_invalid");
        }
        let mut remaining = super::MAX_SOURCE_INPUT_BYTES;
        let bytes = json::compact_record(&value, &mut remaining)?;
        let fingerprint = super::super::digest_value(
            b"hol-guard.command-pack-input.v1\0",
            &json!({"source":value, "trust":metadata.trust, "kind":metadata.kind}),
        )?;
        if inputs
            .insert(
                id,
                Input {
                    bytes,
                    server,
                    trust: metadata.trust,
                    fingerprint,
                },
            )
            .is_some()
        {
            return Err("command_source_extension_duplicate");
        }
        documents.push(document);
    }
    let mut trailing = [0];
    if reader
        .read(&mut trailing)
        .map_err(|_| "command_pack_stream_read_failed")?
        != 0
    {
        return Err("command_pack_stream_trailing_data");
    }
    let mcp_ids = inputs
        .iter()
        .filter(|(_, value)| value.server)
        .map(|(id, _)| id.as_str())
        .collect();
    validation::validate_pack_relationships(&documents, &mcp_ids)?;
    let compatibility: BTreeSet<_> = documents
        .iter()
        .flat_map(|doc| doc.extension.rules.iter())
        .filter(|rule| rule.matcher.is_none())
        .map(|rule| rule.rule_id.as_str())
        .collect();
    if compatibility
        != crate::command_compatibility::compatibility_rule_ids()
            .iter()
            .copied()
            .collect()
    {
        return Err("native_command_compatibility_inventory_mismatch");
    }
    let mcp_inventory = inputs
        .values()
        .filter(|input| input.server)
        .map(|input| mcp::lower(&input.bytes).map(|lowered| json!({"mcp":lowered.wire})))
        .collect::<Result<Vec<_>, _>>()?;
    mcp::validate_inventory(&json!({"extensions":mcp_inventory}))?;
    let owners: BTreeMap<_, _> = documents
        .iter()
        .flat_map(|doc| {
            doc.extension.permissions.iter().map(|permission| {
                (
                    permission.permission_id.as_str(),
                    doc.extension.extension_id.as_str(),
                )
            })
        })
        .collect();
    let references: BTreeMap<_, _> = documents
        .iter()
        .map(|doc| (doc.extension.extension_id.clone(), references(doc, &owners)))
        .collect();
    let extension_interfaces: BTreeSet<String> = inputs.keys().cloned().collect();
    let permission_interfaces: BTreeSet<String> =
        owners.keys().map(|id| (*id).to_owned()).collect();
    // Matcher trees are no longer needed after the globally checked interface
    // has been extracted. Per-pack compilation retains existing native bounds.
    drop(documents);
    let mut writer = ObjectWriter::new(output);
    let mut entries = Vec::new();
    let mut stats = CompilationStats::default();
    compiler.cache.retain(|id, _| inputs.contains_key(id));
    compiler.bytes = compiler.cache.values().map(|(_, _, size)| size).sum();
    for (id, input) in &inputs {
        let commands = if input.server {
            vec![]
        } else {
            vec![input.bytes.as_slice()]
        };
        let servers = if input.server {
            vec![input.bytes.as_slice()]
        } else {
            vec![]
        };
        let related_interfaces: BTreeMap<_, _> = references[id]
            .iter()
            .map(|id| (id, &inputs[id].fingerprint))
            .collect();
        let cache_key = super::super::digest_value(
            b"hol-guard.command-pack-build.v1\0",
            &json!({"input":input.fingerprint,
            "interfaces":related_interfaces, "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"), "semantic_profile":"cpython-3.12-ucd15"}),
        )?;
        let cached = compiler
            .cache
            .get(id)
            .filter(|(key, _, _)| key == &cache_key);
        let compiled = if let Some((_, value, _)) = cached {
            stats.reused += 1;
            Arc::clone(value)
        } else {
            let reused = reuse(id, &cache_key)?;
            let value = if let Some(value) = reused {
                let bytes = serde_json::to_vec(&value.program)
                    .map_err(|_| "command_pack_encoding_failed")?;
                super::super::NativeCommandProgram::validate_compiler_pack_with_interfaces(
                    &bytes,
                    (&extension_interfaces, &permission_interfaces),
                )?;
                mcp::validate_inventory(&value.program)?;
                stats.reused += 1;
                Arc::new(value)
            } else {
                stats.compiled += 1;
                Arc::new(catalog::compile_pack(
                    &commands,
                    &servers,
                    &serde_json::to_vec(&input.trust)
                        .map_err(|_| "command_pack_encoding_failed")?,
                    (&extension_interfaces, &permission_interfaces),
                )?)
            };
            let bytes = if compiler.limit > 0 {
                serde_json::to_vec(&*value)
                    .map_err(|_| "command_pack_encoding_failed")?
                    .len()
            } else {
                0
            };
            if let Some((_, _, size)) = compiler.cache.remove(id) {
                compiler.bytes -= size;
            }
            // A bounded cache is an optimization. Oversized working sets still
            // compile correctly, without increasing policy admission budgets.
            if compiler.limit > 0
                && bytes <= compiler.limit
                && compiler.bytes + bytes <= compiler.limit
            {
                compiler
                    .cache
                    .insert(id.clone(), (cache_key.clone(), Arc::clone(&value), bytes));
                compiler.bytes += bytes;
            }
            value
        };
        let mut program = compiled.program.clone();
        let nodes = program["nodes"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(id, node)| Ok((id.clone(), writer.json(node)?)))
            .collect::<Result<BTreeMap<String, ObjectRef>, &'static str>>()?;
        program["nodes"] =
            serde_json::to_value(nodes).map_err(|_| "command_pack_encoding_failed")?;
        let program_ref = writer.json(&program)?;
        let catalog_ref = writer.json(&compiled.catalog)?;
        let descriptors_ref = writer.json(&json!(compiled.descriptors))?;
        let manifest = json!({
            "schema":"guard.command-policy-pack.v1", "extension_id":id,
            "engine":compiled.implementation_digest, "semantic_profile":"cpython-3.12-ucd15",
            "source_digest":compiled.source_digest, "trust_digest":program["trust_digest"],
            "program_digest":program["program_digest"], "related_interfaces":related_interfaces, "cache_key":cache_key,
            "program":program_ref, "catalog":catalog_ref, "descriptors":descriptors_ref,
        });
        entries.push((id.clone(), writer.json(&manifest)?));
    }
    let index = writer.index(&entries)?;
    stats.retained_encoded_bytes = compiler.bytes;
    Ok((
        json!({"kind":"root", "schema":"guard.command-pack-release.v1",
        "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"), "index":index,
        "extensions":entries.len(), "objects":writer.objects, "object_bytes":writer.bytes,
        "object_bytes_limit":objects::OBJECT_BYTES, "index_fanout":objects::FANOUT,
        "authority":"requires-authenticated-release-binding"}),
        stats,
    ))
}

#[cfg(test)]
#[path = "native_command_source_packs_tests.rs"]
mod tests;
