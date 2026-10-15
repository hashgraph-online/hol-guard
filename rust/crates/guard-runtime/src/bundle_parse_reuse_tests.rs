//! The resident bundle seam keeps the typed response it already validated so
//! offline decisions over thousands of lockfile entries do not re-serialise and
//! re-parse the whole bundle each time.

use guard_command::supply_chain_package_eval::SupplyChainBundleApi;
use serde_json::Value;

use crate::package_authority_op::ResidentBundle;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/supply-chain-eval/cloud-cases.v1.json"
));

fn cached_bundle_json() -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let case = vectors["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == "offline_bundle_block")
        .expect("bundle case");
    let row = &case["rows"]["guard_supply_chain_bundle_cache"][0];
    serde_json::from_str(row["response_json"].as_str().expect("response_json"))
        .expect("response json")
}

#[test]
fn loaded_response_carries_the_parsed_bundle_and_decides_the_same_without_it() {
    let seam = ResidentBundle;
    let raw = cached_bundle_json();
    let loaded = seam
        .load_supply_chain_bundle_response(&raw)
        .expect("bundle loads");
    assert!(loaded.parsed.is_some(), "the validated bundle is retained");

    let mut reparse_only = loaded.clone();
    reparse_only.parsed = None;
    let now = Some(1_779_148_800.0);
    for (name, version) in [
        ("minimist", "1.2.8"),
        ("minimist", "9.9.9"),
        ("other", "1.0.0"),
    ] {
        let reused = seam
            .evaluate_cached_supply_chain_bundle(&loaded, name, Some(version), Some("npm"), now)
            .expect("reused decision");
        let reparsed = seam
            .evaluate_cached_supply_chain_bundle(
                &reparse_only,
                name,
                Some(version),
                Some("npm"),
                now,
            )
            .expect("reparsed decision");
        assert_eq!(reused, reparsed, "{name}@{version}");
    }
    let hit = seam
        .evaluate_cached_supply_chain_bundle(&loaded, "minimist", Some("1.2.8"), Some("npm"), now)
        .expect("decision");
    assert_eq!(hit.get("action"), Some(&Value::String("block".to_owned())));
}
