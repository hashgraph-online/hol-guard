//! Compile canonical sources for this build; no generated file is an input.
#[path = "../../build_support/command_identity.rs"]
mod command_identity;
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
// The canonical corpus plus one acceptance source no longer fits in 4MiB.
const MAX_ENVELOPE_BYTES: u64 = 8 * 1024 * 1024;

fn read_input(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).expect("input inside source tree");
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part);
        assert!(
            !fs::symlink_metadata(&current)
                .expect("source input metadata")
                .file_type()
                .is_symlink(),
            "source input must not traverse symlinks"
        );
    }
    let metadata = fs::metadata(path).expect("source input metadata");
    assert!(
        metadata.is_file() && metadata.len() <= MAX_INPUT_BYTES,
        "source input size/type invalid"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read_to_string(path).expect("source input UTF-8")
}

fn sources(root: &Path, directory: &str, command: bool) -> Vec<String> {
    let path = root.join(directory);
    assert!(
        !fs::symlink_metadata(&path)
            .expect("source directory")
            .file_type()
            .is_symlink(),
        "source directory must not be a symlink"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    let mut paths: Vec<_> = fs::read_dir(path)
        .expect("canonical source directory")
        .map(|entry| entry.expect("source entry").path())
        .filter(|path| {
            path.extension().is_some_and(|v| v == "json")
                && path.file_name().unwrap() != "migration-manifest.json"
        })
        .collect();
    paths.sort();
    assert!(paths.len() <= 512, "canonical source count exceeded");
    paths
        .iter()
        .map(|path| {
            let text = read_input(root, path);
            if command {
                let value: Value = serde_json::from_str(&text).expect("source JSON");
                assert_eq!(
                    path.file_stem().and_then(|v| v.to_str()),
                    value["extension"]["extension_id"].as_str(),
                    "source filename/identity mismatch"
                );
            }
            text
        })
        .collect()
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec(value).expect("generated JSON");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write generated build output");
}

fn main() {
    let package = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let workspace = package.parent().unwrap().parent().unwrap();
    let root = workspace.parent().unwrap();
    let identity = command_identity::emit(workspace);
    let commands = sources(root, "contributions/command-sources", true);
    let mcp = sources(root, "contributions/mcp-servers", false);
    assert!(
        !commands.is_empty() && commands.len() + mcp.len() <= 512,
        "canonical source inventory invalid"
    );
    let trust = read_input(
        root,
        &root.join("contracts/extensions/trust-class-map.v1.json"),
    );
    // Keep raw JSON until the native duplicate-key/depth/budget validator runs.
    // Parsing then reserializing here would silently discard duplicate keys.
    let request = format!(
        r#"{{"schema":"guard.command-extension-build.v1","sources":[{}],"mcp_sources":[{}],"trust":{}}}"#,
        commands.join(","),
        mcp.join(","),
        trust
    );
    assert!(
        request.len() as u64 <= MAX_ENVELOPE_BYTES,
        "canonical source envelope exceeds budget"
    );
    let compiled = guard_command_build::native_command_program::source::compile_build_request(
        request.as_bytes(),
    )
    .unwrap_or_else(|error| panic!("canonical source compilation failed: {error}"));
    assert_eq!(compiled.catalog_projection_kind, "complete");
    assert_eq!(
        compiled.implementation_digest, identity,
        "host/target compiler identity mismatch"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    write_json(
        &out.join("native-command-program.v1.json"),
        &compiled.program,
    );
    write_json(
        &out.join("command-catalog.v1.json"),
        &json!({
            "schema":"guard.command-catalog.v1", "catalog":compiled.catalog,
            "catalog_digest":compiled.program["catalog_digest"], "program_digest":compiled.program["program_digest"],
            "source_digest":compiled.source_digest, "implementation_digest":compiled.implementation_digest,
        }),
    );
    write_json(
        &out.join("native-command-build.v1.json"),
        &serde_json::to_value(compiled).expect("compiled output"),
    );
}
