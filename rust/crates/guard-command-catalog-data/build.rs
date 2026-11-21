//! Compile canonical sources for this build; no generated file is an input.
#[path = "../../build_support/command_identity.rs"]
mod command_identity;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

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

fn sources(root: &Path, entries: &[Value], command: bool) -> Vec<String> {
    let mut remaining = guard_command_build::native_command_program::source::MAX_SOURCE_INPUT_BYTES;
    entries
        .iter()
        .filter(|entry| entry["source"].as_str().unwrap().starts_with("contributions/command-sources/") == command)
        .map(|entry| {
            let path = root.join(entry["source"].as_str().unwrap());
            let mut text = read_input(root, &path);
            {
                let (bytes, _) = guard_command_build::native_command_program::source::validate_and_compact_source(
                    text.as_bytes(), !command, &mut remaining,
                ).unwrap_or_else(|error| panic!("invalid canonical source {}: {error}", path.display()));
                text = String::from_utf8(bytes).expect("validated source UTF-8");
            }
            if command {
                let value: Value = serde_json::from_str(&text).expect("source JSON");
                assert_eq!(
                    path.file_stem().and_then(|v| v.to_str()),
                    value["extension"]["extension_id"].as_str(),
                    "source filename/identity mismatch"
                );
            }
            let value: Value = serde_json::from_str(&text).expect("source JSON");
            let id = if command { value["extension"]["extension_id"].as_str().unwrap().to_owned() }
                else { format!("command.mcp-{}", value["id"].as_str().unwrap().trim_start_matches("mcp.")) };
            assert_eq!(entry["extension_id"], id, "core source identity mismatch");
            text
        })
        .collect()
}

fn write_json(path: &Path, value: &Value) -> Vec<u8> {
    let mut canonical = value.clone();
    canonical.sort_all_objects();
    let mut bytes = serde_json::to_vec(&canonical).expect("generated JSON");
    bytes.push(b'\n');
    fs::write(path, &bytes).expect("write generated build output");
    bytes
}

fn write_embedded_json(out: &Path, name: &str, env_prefix: &str, value: &Value) {
    let bytes = write_json(&out.join(name), value);
    println!(
        "cargo:rustc-env={env_prefix}_SHA256={}",
        hex::encode(Sha256::digest(&bytes))
    );
    println!("cargo:rustc-env={env_prefix}_LEN={}", bytes.len());
    let mut encoder = zstd::stream::read::Encoder::new(bytes.as_slice(), 19).expect("zstd encoder");
    encoder
        .include_checksum(false)
        .expect("zstd checksum option");
    encoder
        .include_contentsize(false)
        .expect("zstd contentsize option");
    encoder.include_dictid(false).expect("zstd dictid option");
    let mut compressed = Vec::new();
    std::io::copy(&mut encoder, &mut compressed).expect("compress packaged JSON");
    let mut decoded = Vec::new();
    ruzstd::decoding::StreamingDecoder::new(compressed.as_slice())
        .expect("decode packaged JSON")
        .read_to_end(&mut decoded)
        .expect("decode packaged JSON");
    assert_eq!(decoded, bytes, "packaged JSON round-trip mismatch");
    fs::write(out.join(format!("{name}.zst")), compressed).expect("write compressed build output");
}

fn trust_map(root: &Path, entries: &[Value]) -> Value {
    let mut classes = json!({"first-party": [], "trusted-library": [], "external": []});
    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let text = read_input(root, &root.join(entry["trust"].as_str().unwrap()));
        let binding: Value = serde_json::from_str(&text).expect("trust binding JSON");
        assert_eq!(binding["schemaVersion"], "guard.extension-trust-binding.v1");
        let extension = binding["extension"]
            .as_str()
            .expect("trust binding identity");
        assert!(seen.insert(extension.to_owned()), "duplicate trust binding");
        let class = binding["trustClass"].as_str().expect("trust binding class");
        assert_eq!(
            entry["extension_id"], extension,
            "core trust identity mismatch"
        );
        assert_ne!(
            class, "external",
            "external contributions must remain opt-in packs"
        );
        classes
            .get_mut(class)
            .and_then(Value::as_array_mut)
            .expect("unknown trust class")
            .push(json!(extension));
    }
    assert!(!seen.is_empty(), "authored trust bindings are missing");
    for values in classes.as_object_mut().unwrap().values_mut() {
        values
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    json!({
        "schemaVersion": "guard.extension-trust-class-map.v1",
        "publishers": {
            "hol": {"id": "hol", "displayName": "HOL"},
            "hol-curated": {"id": "hol-curated", "displayName": "HOL curated library"}
        },
        "classes": classes
    })
}

// No directory enumeration or watches here: optional data is packaged separately.
fn core_entries(root: &Path) -> Vec<Value> {
    let manifest: Value = serde_json::from_str(&read_input(
        root,
        &root.join("contracts/extensions/core-defaults.v1.json"),
    ))
    .expect("core manifest JSON");
    assert_eq!(manifest["schema"], "guard.core-defaults.v1");
    let entries = manifest["entries"].as_array().expect("core entries");
    assert!(
        !entries.is_empty() && entries.len() <= 512,
        "core inventory invalid"
    );
    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let id = entry["extension_id"].as_str().expect("core identity");
        assert!(
            id.starts_with("command.") && !id.contains(['/', '\\']) && seen.insert(id),
            "core identity invalid/duplicate"
        );
        let source = entry["source"].as_str().expect("core source path");
        let expected = if let Some(server) = id.strip_prefix("command.mcp-") {
            format!("contributions/mcp-servers/mcp.{server}.json")
        } else {
            format!("contributions/command-sources/{id}.json")
        };
        assert_eq!(source, expected, "core source path invalid");
        assert_eq!(
            entry["trust"],
            format!("contracts/extensions/trust/{id}.v1.json"),
            "core trust path invalid"
        );
    }
    entries.clone()
}

fn main() {
    let package = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let workspace = package.parent().unwrap().parent().unwrap();
    let root = workspace.parent().unwrap();
    let identity = command_identity::emit(workspace);
    let entries = core_entries(root);
    let commands = sources(root, &entries, true);
    let mcp = sources(root, &entries, false);
    assert!(
        !commands.is_empty() && commands.len() + mcp.len() <= 512,
        "canonical source inventory invalid"
    );
    let trust = trust_map(root, &entries);
    // Each raw record reaches native strict validation independently. Do not
    // normalize authored JSON or construct a formatting-sensitive corpus envelope.
    let commands: Vec<_> = commands.iter().map(|text| text.as_bytes()).collect();
    let mcp: Vec<_> = mcp.iter().map(|text| text.as_bytes()).collect();
    let mut compiled =
        guard_command_build::native_command_program::source::compile_catalog_with_mcp(
            &commands,
            &mcp,
            &serde_json::to_vec(&trust).expect("trust encoding"),
        )
        .unwrap_or_else(|error| panic!("canonical source compilation failed: {error}"));
    assert_eq!(compiled.catalog_projection_kind, "complete");
    assert_eq!(
        compiled.implementation_digest, identity,
        "host/target compiler identity mismatch"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    println!(
        "cargo:rustc-env=GUARD_PACKAGED_PROGRAM_ID={}",
        compiled.program["program_digest"]
            .as_str()
            .expect("program identity")
    );
    let required: Vec<_> = compiled.program["extensions"]
        .as_array()
        .expect("program extensions")
        .iter()
        .filter(|extension| extension["required"] == true || extension["trust_class"] != "external")
        .map(|extension| {
            extension["extension_id"]
                .as_str()
                .expect("extension identity")
        })
        .collect();
    println!(
        "cargo:rustc-env=GUARD_DEFAULT_COMMAND_PACK_IDS={}",
        required.join(",")
    );
    write_json(&out.join("trust-class-map.v1.json"), &trust);
    write_embedded_json(
        &out,
        "native-command-program.v1.json",
        "GUARD_PACKAGED_PROGRAM",
        &compiled.program,
    );
    write_embedded_json(
        &out,
        "command-catalog.v1.json",
        "GUARD_PACKAGED_CATALOG",
        &json!({
            "schema":"guard.command-catalog.v1", "catalog":compiled.catalog,
            "catalog_digest":compiled.program["catalog_digest"], "program_digest":compiled.program["program_digest"],
            "source_digest":compiled.source_digest, "implementation_digest":compiled.implementation_digest,
        }),
    );
    // The export front end reuses the admitted program rather than embedding a
    // second complete copy inside the build envelope.
    compiled.program = Value::Null;
    // The catalog projection already ships inside command-catalog.v1.json; the
    // export front end reinserts it when serving the build envelope.
    compiled.catalog = Value::Null;
    write_embedded_json(
        &out,
        "native-command-build.v1.json",
        "GUARD_PACKAGED_BUILD",
        &serde_json::to_value(compiled).expect("compiled output"),
    );
}
