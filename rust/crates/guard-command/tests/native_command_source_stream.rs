//! Complete-corpus parity through the offline raw-record interface.
use guard_command::native_command_program::source::{compile_build_request, compile_source_stream};
use serde_json::{json, Value};
use std::path::PathBuf;

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn inventory(directory: &str) -> Vec<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
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
        .collect()
}

fn stream(commands: &[Vec<u8>], servers: &[Vec<u8>], trust: &Value) -> Vec<u8> {
    let mut output = b"HGCS\x01".to_vec();
    frame(
        &mut output,
        &serde_json::to_vec(&json!({
            "schema":"guard.command-extension-source-stream.v1",
            "sources":commands.len(),"mcp_sources":servers.len(),"trust":trust
        }))
        .unwrap(),
    );
    for record in commands.iter().chain(servers) {
        frame(&mut output, record);
    }
    output
}

#[test]
fn raw_catalog_over_eight_mebibytes_matches_the_legacy_projection_exactly() {
    let mut commands = inventory("contributions/command-sources");
    let servers = inventory("contributions/mcp-servers");
    let trust: Value = serde_json::from_slice(guard_command_catalog_data::TRUST_MAP_JSON).unwrap();
    let values = |records: &[Vec<u8>]| -> Vec<Value> {
        records
            .iter()
            .map(|bytes| serde_json::from_slice(bytes).unwrap())
            .collect()
    };
    let legacy = compile_build_request(
        &serde_json::to_vec(&json!({
            "schema":"guard.command-extension-build.v1", "sources":values(&commands),
            "mcp_sources":values(&servers), "trust":trust
        }))
        .unwrap(),
    )
    .unwrap();
    commands[0].resize(5 * 1024 * 1024, b' ');
    commands[1].resize(5 * 1024 * 1024, b' ');
    assert!(commands.iter().map(Vec::len).sum::<usize>() > 8 * 1024 * 1024);
    let bytes = stream(&commands, &servers, &trust);
    let actual = compile_source_stream(bytes.as_slice()).unwrap();
    assert_eq!(
        serde_json::to_value(&legacy).unwrap(),
        serde_json::to_value(&actual).unwrap()
    );
    commands.reverse();
    assert_eq!(
        serde_json::to_value(&actual).unwrap(),
        serde_json::to_value(
            compile_source_stream(stream(&commands, &servers, &trust).as_slice()).unwrap()
        )
        .unwrap()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        compile_source_stream(trailing.as_slice()).unwrap_err().code,
        "command_source_stream_trailing_data"
    );
}

#[test]
fn unbound_source_keeps_public_identity_and_external_opt_in() {
    let mut commands = inventory("contributions/command-sources");
    commands.push(include_bytes!("fixtures/command-source-example.v1.json").to_vec());
    let servers = inventory("contributions/mcp-servers");
    let trust: Value = serde_json::from_slice(guard_command_catalog_data::TRUST_MAP_JSON).unwrap();
    let output = compile_source_stream(stream(&commands, &servers, &trust).as_slice()).unwrap();
    let descriptor = output
        .descriptors
        .iter()
        .find(|value| value["id"] == "command.example-cli")
        .unwrap();
    assert_eq!(descriptor["activation"], "opt-in");
    assert_eq!(descriptor["trustClass"], "external");
    assert_eq!(
        descriptor["nativeSource"]["path"],
        "contributions/command-sources/command.example-cli.json"
    );
    assert_eq!(
        descriptor["nativeSource"]["digest"].as_str().unwrap().len(),
        64
    );
}
