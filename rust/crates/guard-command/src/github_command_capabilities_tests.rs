//! Parity test: `classify_github_cli` vs the Python oracle corpus.
//! Oracle generated from `github_command_capabilities.py::classify_github_cli`
//! over `testdata/github_command_capabilities_oracle.json`.

use crate::github_command_capabilities::classify_github_cli;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct OracleRow {
    argv: Vec<String>,
    capability: Option<String>,
    reason_code: Option<String>,
    detail: Option<String>,
    capabilities: Option<Vec<String>>,
}

fn cap_from_str(s: &str) -> Option<crate::github_capability_contract::GitHubCommandCapability> {
    use crate::github_capability_contract::GitHubCommandCapability as C;
    C::ALL.iter().copied().find(|c| c.as_str() == s)
}

#[test]
fn github_cli_classification_matches_python_oracle() {
    let rows: Vec<OracleRow> = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/github_command_capabilities_oracle.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut mismatches = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(expected_cap) = row.capability.as_deref().and_then(cap_from_str) else {
            mismatches.push(format!(
                "#{i} {:?}: oracle had no capability (error row)",
                row.argv
            ));
            continue;
        };
        let got = classify_github_cli(&row.argv);
        let exp_caps: Vec<_> = row
            .capabilities
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|s| cap_from_str(s))
            .collect();
        if got.capability != expected_cap
            || got.capabilities != exp_caps
            || got.reason_code != row.reason_code.as_deref().unwrap_or("")
            || got.detail != row.detail.as_deref().unwrap_or("")
        {
            mismatches.push(format!(
                "#{i} {:?}\n  rust: cap={:?} caps={:?} reason={:?} detail={:?}\n  py:   cap={:?} caps={:?} reason={:?} detail={:?}",
                row.argv,
                got.capability, got.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                got.reason_code, got.detail,
                row.capability, row.capabilities, row.reason_code, row.detail,
            ));
        }
    }
    let mut by_reason = BTreeMap::new();
    for m in &mismatches {
        *by_reason.entry(m.clone()).or_insert(0u32) += 1;
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
