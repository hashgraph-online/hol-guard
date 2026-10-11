//! Package intent targets for workspace scans: one target per inventory item
//! and one for an explicit package spec, built by the shared guard-command
//! helpers. Targets are returned as exact execution dictionaries so the caller
//! can rebuild its intent without re-deriving them.

use guard_command::package_intent_common::PackageIntentTarget;
use guard_command::workspace_inventory::{target_for_package_spec, target_from_inventory_item};
use serde_json::Value;

/// The target for an explicit package spec, from the shared ecosystem dispatch.
pub(crate) fn target_for_spec(ecosystem: &str, spec: &str) -> PackageIntentTarget {
    target_for_package_spec(ecosystem, spec)
}

/// One target per inventory item, from the shared inventory-item derivation.
/// Items that do not carry a string ecosystem and name are rejected.
pub(crate) fn scan_targets(inventory: &[Value]) -> Result<Vec<Value>, String> {
    inventory
        .iter()
        .map(|entry| {
            let item = entry
                .as_object()
                .filter(|item| {
                    item.get("ecosystem").is_some_and(Value::is_string)
                        && item.get("name").is_some_and(Value::is_string)
                })
                .ok_or_else(|| "native_workspace_inventory_invalid".to_owned())?;
            Ok(target_from_inventory_item(item).to_execution_dict())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Vectors recorded from the Python target builders before they were removed.
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../testdata/scan_target_vectors.json"))
            .expect("scan target vectors parse")
    }

    #[test]
    fn inventory_items_match_recorded_python_targets() {
        let vectors = vectors();
        let cases = vectors["items"].as_array().expect("items");
        assert!(cases.len() > 50);
        for case in cases {
            let got = scan_targets(std::slice::from_ref(&case["item"])).expect("targets");
            assert_eq!(got, vec![case["target"].clone()], "item {}", case["item"]);
        }
    }

    #[test]
    fn explicit_specs_match_recorded_python_targets() {
        let vectors = vectors();
        let cases = vectors["specs"].as_array().expect("specs");
        assert!(cases.len() > 150);
        for case in cases {
            let got = target_for_spec(
                case["ecosystem"].as_str().expect("ecosystem"),
                case["spec"].as_str().expect("spec"),
            )
            .to_execution_dict();
            assert_eq!(
                got, case["target"],
                "spec {} {}",
                case["ecosystem"], case["spec"]
            );
        }
    }

    #[test]
    fn malformed_items_are_rejected() {
        assert!(scan_targets(&[json!({"ecosystem": "npm"})]).is_err());
        assert!(scan_targets(&[json!("npm")]).is_err());
    }
}
