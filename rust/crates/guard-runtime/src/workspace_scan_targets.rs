//! Package intent targets for workspace scans: one target per inventory item
//! and one for an explicit package spec, built with the same ecosystem
//! dispatch the Python scan used. Targets are returned as exact execution
//! dictionaries so the caller can rebuild its intent without re-deriving them.

use guard_command::package_intent_common::{
    composer_target, coordinate_target, js_target, python_target, version_target,
    PackageIntentTarget,
};
use serde_json::{Map, Value};

/// The ecosystem dispatch shared by inventory items and explicit specs.
pub(crate) fn target_for_spec(ecosystem: &str, spec: &str) -> PackageIntentTarget {
    match ecosystem {
        "npm" => js_target(spec),
        "pypi" => python_target(spec, false, None, Vec::new()),
        "maven" => coordinate_target(ecosystem, spec),
        "packagist" => composer_target(spec),
        _ => version_target(ecosystem, spec, None),
    }
}

fn string_field<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    item.get(key).and_then(Value::as_str)
}

/// The package spec a lockfile or manifest inventory item stands for.
fn item_spec(item: &Map<String, Value>) -> Option<(String, String)> {
    let ecosystem = string_field(item, "ecosystem")?;
    let name = string_field(item, "name")?;
    let qualified = match string_field(item, "namespace") {
        Some(namespace) => format!("{namespace}/{name}"),
        None => name.to_owned(),
    };
    let suffix = string_field(item, "version")
        .or_else(|| string_field(item, "range"))
        .unwrap_or("");
    let spec = if suffix.is_empty() {
        qualified
    } else {
        let separator = match ecosystem {
            "pypi" => "",
            "maven" | "packagist" => ":",
            _ => "@",
        };
        format!("{qualified}{separator}{suffix}")
    };
    Some((ecosystem.to_owned(), spec))
}

pub(crate) fn scan_targets(inventory: &[Value]) -> Result<Vec<Value>, String> {
    inventory
        .iter()
        .map(|entry| {
            let (ecosystem, spec) = entry
                .as_object()
                .and_then(item_spec)
                .ok_or_else(|| "native_workspace_inventory_invalid".to_owned())?;
            Ok(target_for_spec(&ecosystem, &spec).to_execution_dict())
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
