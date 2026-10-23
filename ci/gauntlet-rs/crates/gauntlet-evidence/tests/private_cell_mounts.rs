use gauntlet_evidence::verify_private_cell_mount_relation;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/private_cell_mount_v1.json")).unwrap()
}

fn run(row: &Value, mountinfo: &str) -> gauntlet_evidence::Result<Value> {
    let providers: Vec<String> = row["provider_mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap().to_owned())
        .collect();
    verify_private_cell_mount_relation(
        &row["plane"],
        &row["rows"],
        row["workspace_source"].as_str().unwrap(),
        &providers,
        row["pid"].as_u64().unwrap(),
        row["prefix"].as_str().unwrap(),
        mountinfo,
    )
}

#[test]
fn python_task_idmap_and_mount_inventory_match() {
    let fixture = fixture();
    assert_eq!(fixture["schema"], "gauntlet-python-private-cell-mount.v1");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/private_cell_custody.py");
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(source).unwrap()))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 26);
    assert_eq!(
        cases.iter().filter(|row| row["accepted"] == true).count(),
        4
    );
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let mountinfo = row["mountinfo"].as_str().unwrap();
        let observed = run(row, mountinfo);
        if row["accepted"] == true {
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                json!({"task_mount_count": row["plane"]["task_mounts"].as_array().unwrap().len(),
                       "kernel_mount_count": mountinfo.lines().count(),
                       "execution_eligible": false}),
                "{name}"
            );
        } else {
            assert_eq!(
                observed.unwrap_err().to_string(),
                row["reason"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}

#[test]
fn oversized_mount_inventory_is_refused() {
    let fixture = fixture();
    let row = &fixture["cases"][0];
    let oversized = "x".repeat(1024 * 1024);
    assert_eq!(
        run(row, &oversized).unwrap_err().to_string(),
        "bounded kernel mount inventory required"
    );
}
