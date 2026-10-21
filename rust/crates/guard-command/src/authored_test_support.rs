//! Full authored-library fixtures, compiled only by tests; never resident inputs.
use crate::native_command_program::{source, NativeCommandProgram};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

pub(crate) fn sources() -> Vec<(Value, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut result = Vec::new();
    for (directory, kind) in [("command-sources", "command"), ("mcp-servers", "mcp")] {
        let mut paths: Vec<_> = fs::read_dir(root.join("contributions").join(directory))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension().is_some_and(|value| value == "json")
                    && path.file_name().unwrap() != "migration-manifest.json"
            })
            .collect();
        paths.sort();
        for path in paths {
            let bytes = fs::read(&path).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            let id = if kind == "command" {
                value["extension"]["extension_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            } else {
                format!(
                    "command.mcp-{}",
                    value["id"].as_str().unwrap().strip_prefix("mcp.").unwrap()
                )
            };
            let binding: Value = serde_json::from_slice(
                &fs::read(root.join(format!("contracts/extensions/trust/{id}.v1.json"))).unwrap(),
            )
            .unwrap();
            let mut trust = trust_map();
            trust["classes"][binding["trustClass"].as_str().unwrap()] = json!([id]);
            result.push((json!({"kind":kind, "trust":trust}), bytes));
        }
    }
    result
}

pub(crate) fn trust_map() -> Value {
    json!({"schemaVersion":"guard.extension-trust-class-map.v1", "publishers":{
        "hol":{"id":"hol", "displayName":"Hashgraph Online"},
        "hol-curated":{"id":"hol-curated", "displayName":"HOL curated library"}},
        "classes":{"first-party":[], "trusted-library":[], "external":[]}})
}

pub(crate) fn stream(sources: &[(Value, Vec<u8>)]) -> Vec<u8> {
    fn frame(stream: &mut Vec<u8>, bytes: &[u8]) {
        stream.extend((bytes.len() as u32).to_be_bytes());
        stream.extend(bytes);
    }
    let mut stream = b"HGPS\x01".to_vec();
    frame(
        &mut stream,
        &serde_json::to_vec(
            &json!({"schema":"guard.command-pack-source-stream.v1", "count":sources.len()}),
        )
        .unwrap(),
    );
    for (metadata, bytes) in sources {
        frame(&mut stream, &serde_json::to_vec(metadata).unwrap());
        frame(&mut stream, bytes);
    }
    stream
}

/// Fixed legacy oracle for aggregate/parity tests, independent of library growth.
pub(crate) fn bounded_catalog() -> &'static source::CompiledSourceCatalog {
    static COMPILED: OnceLock<source::CompiledSourceCatalog> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let core: Value =
            serde_json::from_slice(crate::native_command_catalog::embedded_catalog_bytes())
                .unwrap();
        let mut ids: BTreeSet<_> = core["catalog"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["extension_id"].as_str().unwrap().to_owned())
            .collect();
        ids.extend(
            [
                "command.agentbridge",
                "command.cloud.aws",
                "command.mcp-filesystem",
                "command.mcp-instapods",
            ]
            .map(str::to_owned),
        );
        let sources: Vec<_> = sources()
            .into_iter()
            .filter(|(metadata, _)| {
                metadata["trust"]["classes"]
                    .as_object()
                    .unwrap()
                    .values()
                    .flat_map(|ids| ids.as_array().unwrap())
                    .any(|id| ids.contains(id.as_str().unwrap()))
            })
            .collect();
        assert_eq!(
            sources.len(),
            ids.len(),
            "bounded oracle inventory must be complete"
        );
        let mut trust = trust_map();
        let mut commands = Vec::new();
        let mut servers = Vec::new();
        for (metadata, bytes) in &sources {
            if metadata["kind"] == "command" {
                commands.push(bytes.as_slice());
            } else {
                servers.push(bytes.as_slice());
            }
            for (class, ids) in metadata["trust"]["classes"].as_object().unwrap() {
                trust["classes"][class]
                    .as_array_mut()
                    .unwrap()
                    .extend(ids.as_array().unwrap().iter().cloned());
            }
        }
        let compiled = source::compile_catalog_with_mcp(
            &commands,
            &servers,
            &serde_json::to_vec(&trust).unwrap(),
        )
        .unwrap();
        NativeCommandProgram::validate_compiler_pack(
            &serde_json::to_vec(&compiled.program).unwrap(),
        )
        .unwrap();
        compiled
    })
}

fn full_packs() -> &'static Vec<source::CompiledSourceCatalog> {
    static PACKS: OnceLock<Vec<source::CompiledSourceCatalog>> = OnceLock::new();
    PACKS.get_or_init(|| {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;
        let sources = sources();
        let mut output = Vec::new();
        let root = source::compile_pack_stream(stream(&sources).as_slice(), &mut output).unwrap();
        let objects: BTreeMap<String, Vec<u8>> = output
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
        let bytes = serde_json::to_vec(&root).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        let mut reader = source::PackReleaseReuse::from_bytes(&bytes, &digest, |id: &str| {
            objects.get(id).cloned().ok_or("missing authored object")
        })
        .unwrap();
        sources
            .iter()
            .map(|(metadata, _)| {
                let id = metadata["trust"]["classes"]
                    .as_object()
                    .unwrap()
                    .values()
                    .flat_map(|ids| ids.as_array().unwrap())
                    .next()
                    .unwrap()
                    .as_str()
                    .unwrap();
                reader.read(id, None).unwrap().unwrap()
            })
            .collect()
    })
}

pub(crate) struct AuthoredCatalog {
    pub catalog: Value,
}

pub(crate) fn full_catalog() -> &'static AuthoredCatalog {
    static CATALOG: OnceLock<AuthoredCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut rows: Vec<_> = full_packs()
            .iter()
            .flat_map(|pack| pack.catalog.as_array().unwrap().iter().cloned())
            .collect();
        rows.sort_by(|left, right| {
            left["extension_id"]
                .as_str()
                .cmp(&right["extension_id"].as_str())
        });
        AuthoredCatalog {
            catalog: Value::Array(rows),
        }
    })
}

pub(crate) fn full_program() -> Arc<NativeCommandProgram> {
    static PROGRAM: OnceLock<Arc<NativeCommandProgram>> = OnceLock::new();
    Arc::clone(PROGRAM.get_or_init(|| {
        let catalog = full_catalog().catalog.as_array().unwrap();
        let extensions = catalog
            .iter()
            .map(|row| row["extension_id"].as_str().unwrap().to_owned())
            .collect();
        let permissions = catalog
            .iter()
            .flat_map(|row| row["permissions"].as_array().unwrap())
            .map(|row| row["permission_id"].as_str().unwrap().to_owned())
            .collect();
        let packs = full_packs()
            .iter()
            .map(|pack| {
                NativeCommandProgram::from_bytes_observed(
                    &serde_json::to_vec(&pack.program).unwrap(),
                    &mut |_| {},
                    Some((&extensions, &permissions)),
                )
                .unwrap()
            })
            .collect();
        Arc::new(NativeCommandProgram::combine_admitted_packs(packs).unwrap())
    }))
}

pub(crate) fn catalog_bytes() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let compiled = full_catalog();
    let program = full_program();
    let catalog_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&compiled.catalog).unwrap(),
    ));
    serde_json::to_vec(&json!({"catalog":compiled.catalog,
        "catalog_digest":catalog_digest,
        "program_digest":program.program_digest}))
    .unwrap()
}
