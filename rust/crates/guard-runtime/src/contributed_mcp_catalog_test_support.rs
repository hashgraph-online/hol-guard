//! Test-only source compilation and normal cache admission for the active MCP path.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use base64ct::{Base64, Encoding};
use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_command::native_command_program::{
    packaged_command_program, source, NativeCommandProgram, PackAdmissionBudget,
};
use guard_contracts::NativeCommandControlBindingV1;
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde_json::{json, Value};

pub(super) fn controls(home: &Path, lockdown: bool) -> CompiledNativeCommandControls {
    controls_for(
        home,
        lockdown,
        &["command.mcp-filesystem", "command.mcp-enola"],
        &["command.mcp-filesystem", "command.mcp-enola"],
    )
}

pub(super) fn controls_for(
    home: &Path,
    lockdown: bool,
    optional: &[&str],
    enabled: &[&str],
) -> CompiledNativeCommandControls {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut selected: BTreeSet<String> = packaged_command_program()
        .unwrap()
        .extensions
        .iter()
        .map(|extension| extension.extension_id.clone())
        .collect();
    selected.extend(optional.iter().map(|id| (*id).to_owned()));
    let mut sources = Vec::new();
    for (directory, kind) in [("command-sources", "command"), ("mcp-servers", "mcp")] {
        for path in fs::read_dir(repository.join("contributions").join(directory)).unwrap() {
            let path = path.unwrap().path();
            if path.extension().is_none_or(|extension| extension != "json")
                || path.file_name().unwrap() == "migration-manifest.json"
            {
                continue;
            }
            let bytes = fs::read(path).unwrap();
            let doc: Value = serde_json::from_slice(&bytes).unwrap();
            let id = if kind == "command" {
                doc["extension"]["extension_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            } else {
                format!(
                    "command.mcp-{}",
                    doc["id"].as_str().unwrap().strip_prefix("mcp.").unwrap()
                )
            };
            if !selected.contains(&id) {
                continue;
            }
            let reviewed: Value = serde_json::from_slice(
                &fs::read(repository.join(format!("contracts/extensions/trust/{id}.v1.json")))
                    .unwrap(),
            )
            .unwrap();
            let mut trust = json!({"schemaVersion":"guard.extension-trust-class-map.v1","publishers":{
                "hol":{"id":"hol","displayName":"Hashgraph Online"},"hol-curated":{"id":"hol-curated","displayName":"HOL curated library"}},
                "classes":{"first-party":[],"trusted-library":[],"external":[]}});
            trust["classes"][reviewed["trustClass"].as_str().unwrap()] = json!([id]);
            sources.push((json!({"kind":kind,"trust":trust}), bytes));
        }
    }
    assert_eq!(sources.len(), selected.len());
    fn frame(stream: &mut Vec<u8>, bytes: &[u8]) {
        stream.extend((bytes.len() as u32).to_be_bytes());
        stream.extend(bytes);
    }
    let mut stream = b"HGPS\x01".to_vec();
    frame(
        &mut stream,
        &serde_json::to_vec(
            &json!({"schema":"guard.command-pack-source-stream.v1","count":sources.len()}),
        )
        .unwrap(),
    );
    for (metadata, bytes) in sources {
        frame(&mut stream, &serde_json::to_vec(&metadata).unwrap());
        frame(&mut stream, &bytes);
    }
    let mut output = Vec::new();
    let release = source::compile_pack_stream(stream.as_slice(), &mut output).unwrap();
    let mut objects: BTreeMap<String, Vec<u8>> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let row: Value = serde_json::from_slice(line).unwrap();
            (
                row["sha256"].as_str().unwrap().to_owned(),
                Base64::decode_vec(row["data"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let root = canonical_json_bytes(&release).unwrap();
    let root_digest = digest_bytes(&root);
    let program = NativeCommandProgram::from_integrity_bound_packs(
        &root,
        &root_digest,
        &selected,
        PackAdmissionBudget::resident(),
        |digest| objects.get(digest).cloned().ok_or("fixture_object_missing"),
    )
    .unwrap();
    fn insert(objects: &mut BTreeMap<String, Vec<u8>>, bytes: Vec<u8>) -> Value {
        let digest = digest_bytes(&bytes);
        let reference = json!({"kind":"data","sha256":digest,"length":bytes.len(),"expanded_length":bytes.len()});
        objects.insert(digest, bytes);
        reference
    }
    let root_ref = insert(&mut objects, root);
    let ids: Vec<_> = selected.into_iter().collect();
    let mut next = Value::Null;
    for chunk in ids.chunks(64).rev() {
        next = insert(
            &mut objects,
            canonical_json_bytes(
                &json!({"schema":"guard.command-pack-selection-page.v1","ids":chunk,"next":next}),
            )
            .unwrap(),
        );
    }
    let cache = home.join("mcp-fixture-cache");
    fs::create_dir_all(cache.join("objects")).unwrap();
    fs::create_dir_all(cache.join("sets")).unwrap();
    for (digest, bytes) in objects {
        fs::write(cache.join("objects").join(format!("{digest}.json")), bytes).unwrap();
    }
    fs::write(cache.join("sets").join(format!("{}.json",program.program_digest)),canonical_json_bytes(&json!({"schema":"guard.command-pack-cache.v1","release":root_ref,"selection":next,"selected_count":ids.len()})).unwrap()).unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1","program_digest":program.program_digest,
        "catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,"health":"protected",
        "revision":1,"managed_revision":0,"effective_digest":"","layers":[{
            "schema_version":"1.0.0","kind":"local-admin","catalog_digest":program.catalog_digest,"global_lockdown":lockdown,
            "controls":enabled.iter().map(|id| json!({"target_kind":"extension","target_id":id,"state":"enabled"})).collect::<Vec<_>>()}]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::from_pack_cache(
        &binding,
        &cache,
        PackAdmissionBudget::resident(),
    )
    .unwrap()
}
