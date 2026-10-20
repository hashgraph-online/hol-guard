use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::fs;

#[path = "native_command_program_collection_reader_tests.rs"]
mod collection_reader_tests;
#[path = "native_command_program_pack_cache_tests.rs"]
mod pack_cache_tests;

use crate::native_command_program::authored_test_support::{sources, stream};

#[test]
fn complete_release_is_deterministic_and_reconstructs_exact_native_programs() {
    let mut sources = sources();
    let mut documents = BTreeMap::new();
    for (metadata, source) in &sources {
        let document: SourceDocument = if metadata["kind"] == "command" {
            serde_json::from_slice(source).unwrap()
        } else {
            mcp::lower(source).unwrap().document
        };
        assert!(documents
            .insert(document.extension.extension_id.clone(), document)
            .is_none());
    }
    let extension_ids = documents.keys().cloned().collect();
    let permission_ids = documents
        .values()
        .flat_map(|document| &document.extension.permissions)
        .map(|permission| permission.permission_id.clone())
        .collect();
    // Independent per-pack lowering retains native bounds while the streamed
    // compiler validates every source and the complete relationship interface.
    let expected: BTreeMap<_, _> = sources
        .iter()
        .map(|(metadata, source)| {
            let (commands, servers) = if metadata["kind"] == "command" {
                (vec![source.as_slice()], vec![])
            } else {
                (vec![], vec![source.as_slice()])
            };
            let pack = catalog::compile_pack(
                &commands,
                &servers,
                &serde_json::to_vec(&metadata["trust"]).unwrap(),
                (&extension_ids, &permission_ids),
            )
            .unwrap();
            (
                pack.catalog[0]["extension_id"].as_str().unwrap().to_owned(),
                pack,
            )
        })
        .collect();
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
        seen: &mut BTreeSet<String>,
        expected: &BTreeMap<String, super::super::CompiledSourceCatalog>,
        interfaces: (&BTreeSet<String>, &BTreeSet<String>),
    ) {
        let page: Value =
            serde_json::from_slice(&objects::read_blob(&reference, fetch).unwrap()).unwrap();
        if page["kind"] == "branch" {
            for child in page["children"].as_array().unwrap() {
                visit(
                    serde_json::from_value(child[2].clone()).unwrap(),
                    fetch,
                    seen,
                    expected,
                    interfaces,
                );
            }
        } else {
            for entry in page["entries"].as_array().unwrap() {
                let id = entry[0].as_str().unwrap();
                assert!(
                    seen.insert(id.to_owned()),
                    "duplicate pack in release index"
                );
                let expected_pack = &expected[id];
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
                assert_eq!(
                    program, expected_pack.program,
                    "exact native program for {id}"
                );
                let catalog: Value = serde_json::from_slice(
                    &objects::read_blob(
                        &serde_json::from_value(manifest["catalog"].clone()).unwrap(),
                        fetch,
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(catalog, expected_pack.catalog, "exact catalog for {id}");
                let descriptors: Value = serde_json::from_slice(
                    &objects::read_blob(
                        &serde_json::from_value(manifest["descriptors"].clone()).unwrap(),
                        fetch,
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    descriptors,
                    json!(expected_pack.descriptors),
                    "exact descriptors for {id}"
                );
                super::super::super::NativeCommandProgram::validate_compiler_pack_with_interfaces(
                    &serde_json::to_vec(&program).unwrap(),
                    interfaces,
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
            }
        }
    }
    let mut seen = BTreeSet::new();
    visit(
        serde_json::from_value(root["index"].clone()).unwrap(),
        &mut fetch,
        &mut seen,
        &expected,
        (&extension_ids, &permission_ids),
    );
    assert_eq!(seen, extension_ids);
    assert_eq!(seen.len(), sources.len());
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
