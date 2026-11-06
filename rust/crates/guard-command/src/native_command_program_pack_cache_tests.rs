use super::*;
use crate::native_command_program::{NativeCommandProgram, PackAdmissionBudget};
use sha2::{Digest, Sha256};

fn budget() -> PackAdmissionBudget {
    PackAdmissionBudget {
        packs: 512,
        program_bytes: 128 * 1024 * 1024,
        rules: 16384,
        nodes: 65536,
    }
}

#[test]
fn cached_representation_must_match_independent_collection_identity() {
    let mut output = Vec::new();
    let root = compile_pack_stream(stream(&sources()).as_slice(), &mut output).unwrap();
    let oracle: Value =
        serde_json::from_slice(crate::native_command_program::packaged_command_program_bytes())
            .unwrap();
    let selected: BTreeSet<_> = oracle["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|extension| extension["required"] == true || extension["trust_class"] != "external")
        .map(|extension| extension["extension_id"].as_str().unwrap().to_owned())
        .collect();
    let mut writer = objects::ObjectWriter::new(&mut output);
    let root_ref = writer.json(&root).unwrap();
    let ids: Vec<_> = selected.iter().cloned().collect();
    let mut next = None;
    for page in ids.chunks(64).rev() {
        next = Some(writer.json(&json!({"schema":"guard.command-pack-selection-page.v1", "ids":page, "next":next})).unwrap());
    }
    let set = json!({"schema":"guard.command-pack-cache.v1", "release":root_ref,
        "selection":next, "selected_count":selected.len()});
    let stored: BTreeMap<String, Vec<u8>> = output
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
    let root_bytes = serde_json::to_vec(&root).unwrap();
    let program = NativeCommandProgram::from_integrity_bound_packs(
        &root_bytes,
        &hex::encode(Sha256::digest(&root_bytes)),
        &selected,
        budget(),
        |digest| stored.get(digest).cloned().ok_or("missing"),
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().canonicalize().unwrap();
    fs::create_dir(directory.join("objects")).unwrap();
    fs::create_dir(directory.join("sets")).unwrap();
    for (digest, bytes) in &stored {
        fs::write(
            directory.join("objects").join(format!("{digest}.json")),
            bytes,
        )
        .unwrap();
    }
    let set_path = directory
        .join("sets")
        .join(format!("{}.json", program.program_digest));
    fs::write(&set_path, serde_json::to_vec(&set).unwrap()).unwrap();
    let admitted =
        NativeCommandProgram::from_pack_cache(&directory, &program.program_digest, budget())
            .unwrap();
    assert_eq!(admitted.program_digest, program.program_digest);
    assert_eq!(admitted.catalog_digest, program.catalog_digest);
    assert_eq!(admitted.trust_digest, program.trust_digest);
    for (layer, kind, target, state, allowed) in [
        (
            "local-admin",
            "extension",
            "command.agentbridge",
            "disabled",
            true,
        ),
        (
            "signed-cloud",
            "extension",
            "command.agentbridge",
            "enabled",
            true,
        ),
        (
            "local-admin",
            "permission",
            "command.agentbridge.permission.execute",
            "enabled",
            true,
        ),
        (
            "local-admin",
            "extension",
            "command.agentbridge",
            "enabled",
            false,
        ),
        (
            "local-admin",
            "permission",
            "command.git.permission.missing",
            "enabled",
            false,
        ),
        (
            "local-admin",
            "permission",
            "command.git.permission.missing",
            "disabled",
            false,
        ),
    ] {
        let mut binding: guard_contracts::NativeCommandControlBindingV1 = serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1", "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,
            "health":"protected","revision":1,"managed_revision":0,"effective_digest":"",
            "layers":[{"schema_version":"1.0.0","kind":layer,"catalog_digest":program.catalog_digest,
                "global_lockdown":false,"controls":[{"target_kind":kind,"target_id":target,"state":state}]}],
        })).unwrap();
        binding.effective_digest = binding.compute_effective_digest().unwrap();
        assert_eq!(
            crate::native_command_controls::CompiledNativeCommandControls::from_pack_cache(
                &binding,
                &directory,
                budget()
            )
            .is_ok(),
            allowed,
            "{kind}:{target}:{state}"
        );
        assert!(
            crate::native_command_controls::CompiledNativeCommandControls::for_program(
                &binding,
                std::sync::Arc::new(
                    NativeCommandProgram::from_pack_cache(
                        &directory,
                        &program.program_digest,
                        budget()
                    )
                    .unwrap()
                )
            )
            .is_err()
        );
    }
    let missing: Vec<_> = selected
        .iter()
        .filter(|id| id.as_str() != "command.git")
        .collect();
    assert_eq!(missing.len() + 1, selected.len());
    let bytes = serde_json::to_vec(
        &json!({"schema":"guard.command-pack-selection-page.v1","ids":missing,"next":null}),
    )
    .unwrap();
    let hash = hex::encode(Sha256::digest(&bytes));
    fs::write(
        directory.join("objects").join(format!("{hash}.json")),
        &bytes,
    )
    .unwrap();
    let mut omitted = set.clone();
    omitted["selection"] =
        json!({"sha256":hash,"length":bytes.len(),"expanded_length":bytes.len(),"kind":"data"});
    omitted["selected_count"] = json!(missing.len());
    fs::write(&set_path, serde_json::to_vec(&omitted).unwrap()).unwrap();
    assert_eq!(
        NativeCommandProgram::from_pack_cache(&directory, &program.program_digest, budget())
            .unwrap_err(),
        "native_command_required_pack_missing"
    );
    fs::write(&set_path, serde_json::to_vec(&set).unwrap()).unwrap();
    let forged = "0".repeat(64);
    fs::write(
        directory.join("sets").join(format!("{forged}.json")),
        serde_json::to_vec(&set).unwrap(),
    )
    .unwrap();
    assert_eq!(
        NativeCommandProgram::from_pack_cache(&directory, &forged, budget()).unwrap_err(),
        "native_command_program_binding_mismatch"
    );
    assert!(NativeCommandProgram::from_pack_cache(&directory, "../outside", budget()).is_err());
    let mut truncated = set.clone();
    truncated["selected_count"] = json!(selected.len() + 1);
    fs::write(&set_path, serde_json::to_vec(&truncated).unwrap()).unwrap();
    assert!(
        NativeCommandProgram::from_pack_cache(&directory, &program.program_digest, budget())
            .is_err()
    );
    fs::write(&set_path, serde_json::to_vec(&set).unwrap()).unwrap();
    fs::write(
        directory
            .join("objects")
            .join(format!("{}.json", root_ref.sha256)),
        b"{}",
    )
    .unwrap();
    assert!(
        NativeCommandProgram::from_pack_cache(&directory, &program.program_digest, budget())
            .is_err()
    );
}
