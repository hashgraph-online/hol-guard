use super::*;
use crate::native_command_program::NativeCommandProgram;
use sha2::{Digest, Sha256};

fn budget() -> crate::native_command_program::PackAdmissionBudget {
    crate::native_command_program::PackAdmissionBudget {
        packs: 512,
        program_bytes: 128 * 1024 * 1024,
        rules: 16384,
        nodes: 65536,
    }
}

#[test]
fn selected_release_admission_never_reads_an_unselected_pack() {
    let sources = sources();
    let mut stream_bytes = Vec::new();
    let root = compile_pack_stream(stream(&sources).as_slice(), &mut stream_bytes).unwrap();
    let mut stored: BTreeMap<String, Vec<u8>> = stream_bytes
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
    let id_for = |metadata: &Value, source: &[u8]| {
        let value: Value = serde_json::from_slice(source).unwrap();
        if metadata["kind"] == "mcp" {
            format!(
                "command.mcp-{}",
                value["id"].as_str().unwrap().strip_prefix("mcp.").unwrap()
            )
        } else {
            value["extension"]["extension_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let all: BTreeSet<_> = sources
        .iter()
        .map(|(metadata, source)| id_for(metadata, source))
        .collect();
    let inactive = sources
        .iter()
        .find(|(metadata, _)| {
            metadata["kind"] == "mcp"
                && !metadata["trust"]["classes"]["external"]
                    .as_array()
                    .unwrap()
                    .is_empty()
        })
        .unwrap();
    let inactive = id_for(&inactive.0, &inactive.1);
    let index = serde_json::from_value(root["index"].clone()).unwrap();
    let reference = objects::lookup(&index, all.len(), &inactive, &mut |digest| {
        stored.get(digest).cloned().ok_or("missing")
    })
    .unwrap()
    .unwrap();
    assert!(stored.remove(&reference.sha256).is_some());
    let root_bytes = serde_json::to_vec(&root).unwrap();
    let digest = hex::encode(Sha256::digest(&root_bytes));
    let mut selected = all.clone();
    selected.remove(&inactive);
    let program = NativeCommandProgram::from_integrity_bound_packs(
        &root_bytes,
        &digest,
        &selected,
        budget(),
        |digest| {
            stored
                .get(digest)
                .cloned()
                .ok_or("inactive_payload_was_requested")
        },
    )
    .unwrap();
    assert_eq!(program.extensions.len(), selected.len());
    assert!(program
        .extensions
        .iter()
        .all(|extension| extension.extension_id != inactive));
    assert!(NativeCommandProgram::from_integrity_bound_packs(
        &root_bytes,
        &digest,
        &all,
        budget(),
        |digest| stored.get(digest).cloned().ok_or("missing_active_payload"),
    )
    .is_err());
    assert!(NativeCommandProgram::from_integrity_bound_packs(
        &root_bytes,
        &"0".repeat(64),
        &selected,
        budget(),
        |_| panic!("unverified root fetched objects"),
    )
    .is_err());
    assert!(NativeCommandProgram::from_integrity_bound_packs(
        &root_bytes,
        &digest,
        &selected,
        budget(),
        |_| Ok(b"{}".to_vec()),
    )
    .is_err());
    for limits in [
        crate::native_command_program::PackAdmissionBudget {
            packs: 0,
            ..budget()
        },
        crate::native_command_program::PackAdmissionBudget {
            program_bytes: 1,
            ..budget()
        },
        crate::native_command_program::PackAdmissionBudget {
            rules: 0,
            ..budget()
        },
        crate::native_command_program::PackAdmissionBudget {
            nodes: 0,
            ..budget()
        },
    ] {
        assert!(NativeCommandProgram::from_integrity_bound_packs(
            &root_bytes,
            &digest,
            &selected,
            limits,
            |digest| stored.get(digest).cloned().ok_or("missing"),
        )
        .is_err());
    }
}
