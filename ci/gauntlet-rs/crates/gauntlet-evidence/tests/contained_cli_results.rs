use gauntlet_evidence::verify_contained_cli_results;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn exact_python_contained_cli_result_loop_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/contained_cli_results_v1.json")).unwrap();
    assert_eq!(
        fixture["schema"],
        "gauntlet-python-contained-cli-results.v1"
    );
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/private_cell_runtime_custody.py");
    let bytes = std::fs::read(source).unwrap();
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(bytes))
    );
    let rows = fixture["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 26);
    assert_eq!(rows.iter().filter(|row| row["accepted"] == true).count(), 6);
    for row in rows {
        let observed =
            verify_contained_cli_results(&row["plane"], &row["settings"], &row["agent_identity"]);
        let name = row["name"].as_str().unwrap();
        if row["accepted"] == true {
            let accepted = observed.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(accepted["execution_eligible"], false, "{name}");
            assert_eq!(
                accepted["checked_executions"],
                row["plane"]["executions"].as_array().unwrap().len(),
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
