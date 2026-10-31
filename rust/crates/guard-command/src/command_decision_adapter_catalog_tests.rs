//! The shipped catalog's risk classes against the effect vocabulary.

use super::command_risk_effects;
use serde_json::Value;
use std::collections::BTreeSet;

/// Every risk class the packaged catalog ships that `command_risk_effects`
/// does not name. The catalog is authored outside this table, so the gap is
/// expected; pinning it means a newly shipped class is a decision someone
/// makes rather than one the `PROCESS_EXECUTION` fallback quietly absorbs.
/// Map a class and drop it from here.
const UNMAPPED_SHIPPED_RISK_CLASSES: [&str; 3] =
    ["credential_access", "permission_change", "remote_execution"];

fn strings(value: &Value) -> impl Iterator<Item = String> + '_ {
    value
        .as_array()
        .expect("risk_classes is an array")
        .iter()
        .map(|class| class.as_str().expect("risk class is a string").to_owned())
}

fn shipped_risk_classes() -> BTreeSet<String> {
    let catalog: Value = serde_json::from_slice(guard_command_catalog_data::CATALOG_JSON).unwrap();
    let mut classes = BTreeSet::new();
    for extension in catalog["catalog"].as_array().unwrap() {
        classes.extend(strings(&extension["risk_classes"]));
        for rule in extension["rules"].as_array().unwrap() {
            classes.extend(strings(&rule["risk_classes"]));
        }
    }
    classes
}

#[test]
fn the_packaged_catalog_ships_exactly_the_recorded_unmapped_classes() {
    let shipped = shipped_risk_classes();
    assert!(!shipped.is_empty());
    let unmapped: BTreeSet<&str> = shipped
        .iter()
        .map(String::as_str)
        .filter(|class| command_risk_effects(class).is_none())
        .collect();
    assert_eq!(unmapped, BTreeSet::from(UNMAPPED_SHIPPED_RISK_CLASSES));
}
