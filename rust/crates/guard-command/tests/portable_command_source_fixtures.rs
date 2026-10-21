//! Every portable command-source fixture passes against the current evaluator.
//!
//! The authoring script checks these only in the nightly extension builder, so
//! an evaluator change could leave a fixture's expectation stale until then.

use base64::{engine::general_purpose::STANDARD, Engine};
use guard_command::native_command_program::source::{
    compile_pack_stream, lookup_pack, read_pack_blob, run_fixtures,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf};

fn fixture_paths() -> Vec<PathBuf> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .expect("fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("command-source-") && name.ends_with(".v1.json")
                })
        })
        .collect();
    paths.sort();
    paths
}

fn validation_catalog() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let records = |directory: &str| {
        let mut paths: Vec<_> = std::fs::read_dir(root.join(directory))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
                    && path.file_name().unwrap() != "migration-manifest.json"
            })
            .collect();
        paths.sort();
        paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect::<Vec<_>>()
    };
    let commands = records("contributions/command-sources");
    let servers = records("contributions/mcp-servers");
    let mut trust: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/trust-class-map.v1.json"
    )))
    .unwrap();
    for class in trust["classes"].as_object_mut().unwrap().values_mut() {
        *class = json!([]);
    }
    fn frame(stream: &mut Vec<u8>, bytes: &[u8]) {
        stream.extend((bytes.len() as u32).to_be_bytes());
        stream.extend(bytes);
    }
    let count = commands.len() + servers.len();
    let mut stream = b"HGPS\x01".to_vec();
    frame(
        &mut stream,
        &serde_json::to_vec(&json!({
            "schema":"guard.command-pack-source-stream.v1", "count":count
        }))
        .unwrap(),
    );
    let mut ids = Vec::new();
    for (mcp, bytes) in commands
        .iter()
        .map(|bytes| (false, bytes))
        .chain(servers.iter().map(|bytes| (true, bytes)))
    {
        let source: Value = serde_json::from_slice(bytes).unwrap();
        let id = if mcp {
            format!(
                "command.mcp-{}",
                source["id"].as_str().unwrap().strip_prefix("mcp.").unwrap()
            )
        } else {
            source["extension"]["extension_id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let binding: Value = serde_json::from_slice(
            &std::fs::read(
                root.join("contracts/extensions/trust")
                    .join(format!("{id}.v1.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(binding["schemaVersion"], "guard.extension-trust-binding.v1");
        assert_eq!(binding["extension"], id);
        let mut source_trust = trust.clone();
        source_trust["classes"][binding["trustClass"].as_str().unwrap()] = json!([id]);
        frame(
            &mut stream,
            &serde_json::to_vec(&json!({
                "kind":if mcp { "mcp" } else { "command" }, "trust":source_trust
            }))
            .unwrap(),
        );
        frame(&mut stream, bytes);
        ids.push(id);
    }
    // Validate the complete release through the production pack compiler; the
    // fixture interface needs metadata, never a monolithic native program.
    let mut output = Vec::new();
    let release = compile_pack_stream(stream.as_slice(), &mut output)
        .expect("canonical native release validates before fixture simulation");
    assert_eq!(release["extensions"], count);
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
    let mut fetch = |id: &str| {
        objects
            .get(id)
            .cloned()
            .ok_or("missing fixture pack object")
    };
    let index = serde_json::from_value(release["index"].clone()).unwrap();
    let mut catalog = BTreeMap::new();
    for id in ids {
        let reference = lookup_pack(&index, count, &id, &mut fetch)
            .unwrap()
            .unwrap();
        let manifest: Value =
            serde_json::from_slice(&read_pack_blob(&reference, &mut fetch).unwrap()).unwrap();
        let rows: Vec<Value> = serde_json::from_slice(
            &read_pack_blob(
                &serde_json::from_value(manifest["catalog"].clone()).unwrap(),
                &mut fetch,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["extension_id"], id);
        assert!(catalog
            .insert(id, rows.into_iter().next().unwrap())
            .is_none());
    }
    assert_eq!(catalog.len(), count);
    Value::Array(catalog.into_values().collect())
}

#[test]
fn every_portable_command_source_fixture_passes() {
    let paths = fixture_paths();
    assert!(
        !paths.is_empty(),
        "no portable command-source fixtures found"
    );
    let catalog = validation_catalog();
    let mut failures = Vec::new();
    for path in &paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let mut fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        if fixture["build"]["base"] == "packaged" {
            fixture["build"]
                .as_object_mut()
                .unwrap()
                .entry("validation_base")
                .or_insert_with(|| json!({"catalog":catalog,"programs":[]}));
        }
        let result = match run_fixtures(&serde_json::to_vec(&fixture).unwrap()) {
            Ok(result) => result,
            Err(error) => {
                failures.push(format!("{name}: {error}"));
                continue;
            }
        };
        assert_eq!(result["target_commands_executed"], 0, "{name}");
        for case in result["cases"].as_array().into_iter().flatten() {
            if case["passed"] != true {
                failures.push(format!(
                    "{name}: {} expected {} {} got {} {}",
                    case["id"],
                    case["expected_action"],
                    case["expected_effective_segments"],
                    case["actual_action"],
                    case["actual_effective_segments"],
                ));
            }
        }
        if result["ok"] != true && !failures.iter().any(|line| line.starts_with(&name)) {
            failures.push(format!("{name}: not ok"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
