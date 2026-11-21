//! Release default selection and reviewed resident-core admission.
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(super) fn select(input: &Value) -> super::Result<Value> {
    let catalogs = input["catalogs"].as_array().ok_or(super::INVALID)?;
    let mut selected = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for catalog in catalogs {
        let identity = catalog["extension_id"].as_str().ok_or(super::INVALID)?;
        if !identities.insert(identity) {
            return Err("duplicate release policy identity");
        }
        if catalog["enabled"].as_bool().ok_or(super::INVALID)? {
            if catalog["trust_class"] == "external" {
                return Err("external policy cannot be selected by release defaults");
            }
            selected.insert(identity);
        }
    }
    if let Some(core) = input.get("core_defaults") {
        if !super::fields(core, &["schema", "entries"])
            || core["schema"] != "guard.core-defaults.v1"
        {
            return Err("reviewed core inventory is invalid");
        }
        let rows = core["entries"]
            .as_array()
            .filter(|rows| !rows.is_empty())
            .ok_or("reviewed core inventory entries are invalid")?;
        let mut expected = BTreeSet::new();
        for row in rows {
            if !super::fields(row, &["extension_id", "source", "trust"]) {
                return Err("reviewed core inventory entries are invalid");
            }
            let identity = row["extension_id"]
                .as_str()
                .filter(|id| super::matches(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$", id))
                .ok_or("reviewed core inventory entries are invalid")?;
            if !expected.insert(identity) {
                return Err("installed defaults differ from the reviewed resident core inventory");
            }
        }
        if expected != selected {
            return Err("installed defaults differ from the reviewed resident core inventory");
        }
    }
    Ok(json!({"selected_ids": selected}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({"catalogs":[
            {"extension_id":"command.core","enabled":true,"trust_class":"first-party"},
            {"extension_id":"command.optional","enabled":false,"trust_class":"external"}
        ],"core_defaults":{"schema":"guard.core-defaults.v1","entries":[
            {"extension_id":"command.core","source":"reviewed","trust":"reviewed"}
        ]}})
    }

    #[test]
    fn release_defaults_accept_exact_core_and_legacy_absence() {
        let mut input = request();
        assert_eq!(
            select(&input).unwrap(),
            json!({"selected_ids":["command.core"]})
        );
        input.as_object_mut().unwrap().remove("core_defaults");
        assert_eq!(
            select(&input).unwrap(),
            json!({"selected_ids":["command.core"]})
        );
    }

    #[test]
    fn release_defaults_reject_external_and_changed_core() {
        let mut input = request();
        input["catalogs"][1]["enabled"] = json!(true);
        assert!(select(&input).unwrap_err().contains("external policy"));
        for selected in [
            json!([]),
            json!([{"extension_id":"command.other","enabled":true,"trust_class":"first-party"}]),
        ] {
            input = request();
            input["catalogs"] = selected;
            assert!(select(&input).unwrap_err().contains("defaults differ"));
        }
    }

    #[test]
    fn release_defaults_reject_duplicate_malformed_and_wrong_schema_core() {
        let mut input = request();
        let row = input["core_defaults"]["entries"][0].clone();
        input["core_defaults"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(select(&input).unwrap_err().contains("defaults differ"));
        input = request();
        input["core_defaults"]["schema"] = json!("unknown");
        assert!(select(&input).unwrap_err().contains("inventory is invalid"));
        input = request();
        input["core_defaults"]["entries"][0]["extension_id"] = json!("../invalid");
        assert!(select(&input).unwrap_err().contains("entries are invalid"));
        input = request();
        input["core_defaults"]["entries"][0]["extra"] = json!(true);
        assert!(select(&input).unwrap_err().contains("entries are invalid"));
    }
}
