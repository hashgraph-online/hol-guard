use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{fs, path::PathBuf};

#[path = "native_command_program_collection_reader_tests.rs"]
mod collection_reader_tests;
#[path = "native_command_program_pack_cache_tests.rs"]
mod pack_cache_tests;

fn frame(stream: &mut Vec<u8>, bytes: &[u8]) {
    stream.extend((bytes.len() as u32).to_be_bytes());
    stream.extend(bytes);
}

fn sources() -> Vec<(Value, Vec<u8>)> {
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
            let mut trust = json!({"schemaVersion":"guard.extension-trust-class-map.v1", "publishers":{
                "hol":{"id":"hol", "displayName":"Hashgraph Online"}, "hol-curated":{"id":"hol-curated", "displayName":"HOL curated library"}},
                "classes":{"first-party":[], "trusted-library":[], "external":[]}});
            trust["classes"][binding["trustClass"].as_str().unwrap()] = json!([id]);
            result.push((json!({"kind":kind, "trust":trust}), bytes));
        }
    }
    result
}

fn stream(sources: &[(Value, Vec<u8>)]) -> Vec<u8> {
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

#[test]
fn complete_release_is_deterministic_and_reconstructs_exact_native_programs() {
    let mut sources = sources();
    let mut trust = sources[0].0["trust"].clone();
    for ids in trust["classes"].as_object_mut().unwrap().values_mut() {
        *ids = json!([]);
    }
    let mut commands = Vec::new();
    let mut servers = Vec::new();
    for (metadata, source) in &sources {
        if metadata["kind"] == "command" {
            commands.push(source.as_slice());
        } else {
            servers.push(source.as_slice());
        }
        for (class, ids) in metadata["trust"]["classes"].as_object().unwrap() {
            trust["classes"][class]
                .as_array_mut()
                .unwrap()
                .extend(ids.as_array().unwrap().iter().cloned());
        }
    }
    let legacy = catalog::compile_catalog_with_mcp(
        &commands,
        &servers,
        &serde_json::to_vec(&trust).unwrap(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    let root = compile_pack_stream(stream(&sources).as_slice(), &mut bytes).unwrap();
    sources.reverse();
    let mut reversed = Vec::new();
    assert_eq!(
        compile_pack_stream(stream(&sources).as_slice(), &mut reversed).unwrap(),
        root
    );
    assert_eq!(bytes, reversed);
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
    let mut fetch = |id: &str| objects.get(id).cloned().ok_or("missing");
    fn visit(
        reference: objects::ObjectRef,
        fetch: &mut impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
        count: &mut usize,
        legacy: &super::super::CompiledSourceCatalog,
    ) {
        let page: Value =
            serde_json::from_slice(&objects::read_blob(&reference, fetch).unwrap()).unwrap();
        if page["kind"] == "branch" {
            for child in page["children"].as_array().unwrap() {
                visit(
                    serde_json::from_value(child[2].clone()).unwrap(),
                    fetch,
                    count,
                    legacy,
                );
            }
        } else {
            for entry in page["entries"].as_array().unwrap() {
                let manifest: Value = serde_json::from_slice(
                    &objects::read_blob(&serde_json::from_value(entry[1].clone()).unwrap(), fetch)
                        .unwrap(),
                )
                .unwrap();
                let mut program: Value = serde_json::from_slice(
                    &objects::read_blob(
                        &serde_json::from_value(manifest["program"].clone()).unwrap(),
                        fetch,
                    )
                    .unwrap(),
                )
                .unwrap();
                for node in program["nodes"].as_object_mut().unwrap().values_mut() {
                    *node = serde_json::from_slice(
                        &objects::read_blob(&serde_json::from_value(node.clone()).unwrap(), fetch)
                            .unwrap(),
                    )
                    .unwrap();
                }
                for (id, node) in program["nodes"].as_object().unwrap() {
                    assert_eq!(Some(node), legacy.program["nodes"].get(id));
                }
                for rule in program["rules"].as_array().unwrap() {
                    assert_eq!(
                        Some(rule),
                        legacy.program["rules"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|candidate| candidate["rule_id"] == rule["rule_id"])
                    );
                }
                let catalog: Value = serde_json::from_slice(
                    &objects::read_blob(
                        &serde_json::from_value(manifest["catalog"].clone()).unwrap(),
                        fetch,
                    )
                    .unwrap(),
                )
                .unwrap();
                for row in catalog.as_array().unwrap() {
                    assert_eq!(
                        Some(row),
                        legacy
                            .catalog
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|candidate| candidate["extension_id"] == row["extension_id"])
                    );
                }
                let descriptors: Value = serde_json::from_slice(
                    &objects::read_blob(
                        &serde_json::from_value(manifest["descriptors"].clone()).unwrap(),
                        fetch,
                    )
                    .unwrap(),
                )
                .unwrap();
                for descriptor in descriptors.as_array().unwrap() {
                    assert!(
                        legacy.descriptors.contains(descriptor),
                        "public contribution descriptor must remain byte-equivalent"
                    );
                }
                super::super::super::NativeCommandProgram::validate_compiler_pack(
                    &serde_json::to_vec(&program).unwrap(),
                )
                .unwrap();
                let own = program["extensions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|extension| extension["extension_id"] == entry[0])
                    .unwrap();
                if own["trust_class"] == "external" {
                    assert_eq!(own["activation"], "opt-in");
                }
                *count += 1;
            }
        }
    }
    let mut count = 0;
    visit(
        serde_json::from_value(root["index"].clone()).unwrap(),
        &mut fetch,
        &mut count,
        &legacy,
    );
    assert_eq!(count, sources.len());
}

#[test]
fn incomplete_duplicate_trailing_and_untrusted_records_cannot_emit_a_root() {
    let sources = sources();
    let mut duplicate = sources.clone();
    duplicate.push(sources[0].clone());
    assert_eq!(
        compile_pack_stream(stream(&duplicate).as_slice(), Vec::new()).unwrap_err(),
        "command_source_extension_duplicate"
    );
    let mut truncated = stream(&sources);
    truncated.pop();
    assert_eq!(
        compile_pack_stream(truncated.as_slice(), Vec::new()).unwrap_err(),
        "command_pack_stream_truncated"
    );
    let mut trailing = stream(&sources);
    trailing.push(0);
    assert_eq!(
        compile_pack_stream(trailing.as_slice(), Vec::new()).unwrap_err(),
        "command_pack_stream_trailing_data"
    );
    let mut bad = sources;
    bad[0].1 = b"{\"schema\":0,\"schema\":1}".to_vec();
    assert!(compile_pack_stream(stream(&bad).as_slice(), Vec::new()).is_err());
}

fn synthetic(index: usize) -> (Value, Vec<u8>) {
    let id = format!("command.scale-{index}");
    let text = include_str!("../tests/fixtures/command-source-example.v1.json")
        .replace("command.example-cli", &id)
        .replace("example-cli", &format!("scale-{index}"));
    let trust = json!({"schemaVersion":"guard.extension-trust-class-map.v1", "publishers":{
        "hol":{"id":"hol", "displayName":"Hashgraph Online"}, "hol-curated":{"id":"hol-curated", "displayName":"HOL curated library"}},
        "classes":{"first-party":[], "trusted-library":[], "external":[id]}});
    (json!({"kind":"command", "trust":trust}), text.into_bytes())
}

#[test]
fn independent_sources_exceed_the_legacy_count_without_changing_its_limits() {
    let mut sources = sources();
    sources.extend((0..520).map(synthetic));
    let root = compile_pack_stream(stream(&sources).as_slice(), std::io::sink()).unwrap();
    assert_eq!(root["extensions"].as_u64().unwrap() as usize, sources.len());
    assert!(sources.len() > 512);
}

#[test]
fn cross_pack_relationships_are_checked_before_output() {
    let mut sources = sources();
    let (metadata, bytes) = synthetic(0);
    let mut one: Value = serde_json::from_slice(&bytes).unwrap();
    one["extension"]["dependencies"] = json!(["command.missing"]);
    sources.push((metadata.clone(), serde_json::to_vec(&one).unwrap()));
    let mut output = Vec::new();
    assert_eq!(
        compile_pack_stream(stream(&sources).as_slice(), &mut output).unwrap_err(),
        "command_source_dependency_missing"
    );
    assert!(output.is_empty());
    let (other_metadata, other_bytes) = synthetic(1);
    let mut other: Value = serde_json::from_slice(&other_bytes).unwrap();
    one["extension"]["dependencies"] = json!(["command.scale-1"]);
    other["extension"]["dependencies"] = json!(["command.scale-0"]);
    *sources.last_mut().unwrap() = (metadata, serde_json::to_vec(&one).unwrap());
    sources.push((other_metadata, serde_json::to_vec(&other).unwrap()));
    assert_eq!(
        compile_pack_stream(stream(&sources).as_slice(), &mut output).unwrap_err(),
        "command_source_dependency_cycle_or_depth"
    );
    assert!(output.is_empty());
}

#[test]
fn incremental_compilation_matches_clean_and_revalidates_raw_sources() {
    let mut sources = sources();
    sources.push(synthetic(0));
    let mut compiler = PackCompiler::default();
    let mut first = Vec::new();
    let (root, stats) = compiler
        .compile(stream(&sources).as_slice(), &mut first)
        .unwrap();
    assert_eq!(stats.compiled, sources.len());
    let mut repeated = Vec::new();
    let (again, stats) = compiler
        .compile(stream(&sources).as_slice(), &mut repeated)
        .unwrap();
    assert_eq!((stats.compiled, stats.reused), (0, sources.len()));
    assert_eq!(root, again);
    assert_eq!(first, repeated);
    assert!(stats.retained_encoded_bytes <= CACHE_BYTES);
    let mut source: Value = serde_json::from_slice(&sources.last().unwrap().1).unwrap();
    source["extension"]["description"] = json!("Updated description");
    sources.last_mut().unwrap().1 = serde_json::to_vec(&source).unwrap();
    let mut cached = Vec::new();
    let (changed, stats) = compiler
        .compile(stream(&sources).as_slice(), &mut cached)
        .unwrap();
    assert_eq!((stats.compiled, stats.reused), (1, sources.len() - 1));
    let mut clean = Vec::new();
    assert_eq!(
        compile_pack_stream(stream(&sources).as_slice(), &mut clean).unwrap(),
        changed
    );
    assert_eq!(cached, clean);
    // A hit cannot skip strict JSON decoding, ownership or global validation.
    sources.last_mut().unwrap().1 = b"{\"schema\":0,\"schema\":1}".to_vec();
    let mut rejected = Vec::new();
    assert!(compiler
        .compile(stream(&sources).as_slice(), &mut rejected)
        .is_err());
    assert!(rejected.is_empty());
}

#[test]
fn authenticated_release_reuse_matches_cold_output_without_process_cache() {
    let mut sources = sources();
    sources.push(synthetic(0));
    let mut cold = Vec::new();
    let root = compile_pack_stream(stream(&sources).as_slice(), &mut cold).unwrap();
    let objects: BTreeMap<String, Vec<u8>> = cold
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
    let fetch = |id: &str| objects.get(id).cloned().ok_or("missing");
    let mut reuse = PackReleaseReuse::new(&root, fetch).unwrap();
    let mut compiler = PackCompiler {
        limit: 0,
        ..PackCompiler::default()
    };
    let mut warm = Vec::new();
    let (again, stats) = compiler
        .compile_reusing(stream(&sources).as_slice(), &mut warm, &mut reuse)
        .unwrap();
    assert_eq!(
        (stats.compiled, stats.reused, stats.retained_encoded_bytes),
        (0, sources.len(), 0)
    );
    assert_eq!(again, root);
    assert_eq!(warm, cold);
    let mut changed: Value = serde_json::from_slice(&sources.last().unwrap().1).unwrap();
    changed["extension"]["description"] = json!("One source edit across compiler processes");
    sources.last_mut().unwrap().1 = serde_json::to_vec(&changed).unwrap();
    warm.clear();
    let (updated, stats) = compiler
        .compile_reusing(stream(&sources).as_slice(), &mut warm, &mut reuse)
        .unwrap();
    assert_eq!((stats.compiled, stats.reused), (1, sources.len() - 1));
    cold.clear();
    assert_eq!(
        compile_pack_stream(stream(&sources).as_slice(), &mut cold).unwrap(),
        updated
    );
    assert_eq!(warm, cold);
    // Current invalid source relationships still reject before cache lookup.
    changed["extension"]["dependencies"] = json!(["command.missing"]);
    sources.last_mut().unwrap().1 = serde_json::to_vec(&changed).unwrap();
    warm.clear();
    assert!(compiler
        .compile_reusing(stream(&sources).as_slice(), &mut warm, &mut reuse)
        .is_err());
    assert!(warm.is_empty());
    // Replacing a disk object cannot replace the authenticated Merkle path.
    let mut corrupt = PackReleaseReuse::new(&root, |_: &str| Ok(b"{}".to_vec())).unwrap();
    assert!(corrupt.get("command.git", "irrelevant").is_err());
    let mut wrong_engine = root;
    wrong_engine["engine"] = json!("0".repeat(64));
    assert!(PackReleaseReuse::new(&wrong_engine, |_: &str| Err("unused")).is_err());
}

#[test]
fn referenced_interface_changes_invalidate_dependants_and_removed_owners_fail() {
    let mut sources = sources();
    let (metadata, bytes) = synthetic(0);
    let mut owner: Value = serde_json::from_slice(&bytes).unwrap();
    owner["extension"]["dependencies"] = json!(["command.scale-1"]);
    sources.push((metadata, serde_json::to_vec(&owner).unwrap()));
    sources.push(synthetic(1));
    let mut compiler = PackCompiler::default();
    compiler
        .compile(stream(&sources).as_slice(), std::io::sink())
        .unwrap();
    let last = sources.last_mut().unwrap();
    let mut related: Value = serde_json::from_slice(&last.1).unwrap();
    related["extension"]["description"] = json!("Related interface input changed");
    last.1 = serde_json::to_vec(&related).unwrap();
    let (_, stats) = compiler
        .compile(stream(&sources).as_slice(), std::io::sink())
        .unwrap();
    assert_eq!((stats.compiled, stats.reused), (2, sources.len() - 2));
    sources.pop();
    let mut rejected = Vec::new();
    assert_eq!(
        compiler
            .compile(stream(&sources).as_slice(), &mut rejected)
            .unwrap_err(),
        "command_source_dependency_missing"
    );
    assert!(rejected.is_empty());
}

#[test]
fn cache_working_set_over_budget_compiles_without_retaining_unbounded_results() {
    let sources = sources();
    let mut compiler = PackCompiler {
        limit: 1,
        ..PackCompiler::default()
    };
    for _ in 0..2 {
        let (_, stats) = compiler
            .compile(stream(&sources).as_slice(), std::io::sink())
            .unwrap();
        assert_eq!(stats.compiled, sources.len());
        assert_eq!(stats.reused, 0);
        assert_eq!(stats.retained_encoded_bytes, 0);
    }
    assert!(compiler.cache.is_empty());
}
