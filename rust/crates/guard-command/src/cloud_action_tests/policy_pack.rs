//! Policy pack validation and the `policy`/`classify` JSON-lines ops.

use crate::cloud_pack_cli::answer;
use crate::cloud_policy_pack::{policy_pack_from_value, shipped, Preset};
use serde_json::{json, Value};

const BALANCED: &str =
    include_str!("../../../../../contributions/cloud-policy-packs/balanced.json");

fn balanced() -> Value {
    serde_json::from_str(BALANCED).unwrap()
}

fn refused(change: impl FnOnce(&mut Value)) -> (&'static str, String) {
    let mut pack = balanced();
    change(&mut pack);
    let error = policy_pack_from_value(pack).unwrap_err();
    (error.code, error.pointer)
}

#[test]
fn the_shipped_documents_parse_to_the_shipped_packs() {
    for preset in Preset::ALL {
        assert_eq!(shipped(preset).preset, preset);
    }
    let parsed = policy_pack_from_value(balanced()).unwrap();
    assert_eq!(parsed.digest(), shipped(Preset::Balanced).digest());
}

#[test]
fn validation_refuses_unsafe_policy_packs() {
    assert_eq!(
        refused(|pack| pack["schema"] = json!("guard.cloud-policy-pack.v0")).0,
        "policy_pack_schema_unsupported"
    );
    assert_eq!(
        refused(|pack| pack["rules"][1]["rule"]["rule_id"] =
            pack["rules"][0]["rule"]["rule_id"].clone()),
        (
            "policy_pack_rule_duplicate",
            "/rules/1/rule/rule_id".to_owned()
        )
    );
    assert_eq!(
        refused(|pack| pack["rules"][0]["rule"]["rule_id"] = json!("strict.r00.draft")),
        ("policy_pack_rule_invalid", "/rules/0/rule".to_owned())
    );
    assert_eq!(
        refused(
            |pack| pack["rules"][4]["rule"]["facts"]["windows"][0]["window"] = json!("deletes_1d")
        ),
        ("policy_pack_window_undeclared", "/rules/4/rule".to_owned())
    );
    assert_eq!(
        refused(|pack| pack["unclassified"]["action"] = json!("allow")).0,
        "policy_pack_unclassified_lenient"
    );
    assert_eq!(
        refused(|pack| {
            pack["unclassified"] =
                json!({"action": "require-reapproval", "destructive_name_action": "review"})
        })
        .0,
        "policy_pack_unclassified_lenient"
    );
    assert_eq!(
        refused(|pack| pack["windows"][0]["seconds"] = json!(0)).0,
        "policy_pack_invalid"
    );
    assert_eq!(
        refused(|pack| pack["rules"] = json!([])).0,
        "policy_pack_limit"
    );
    assert_eq!(
        refused(|pack| pack["extra"] = json!(true)).0,
        "policy_pack_invalid"
    );
}

#[test]
fn the_json_lines_tools_answer_policy_and_classify() {
    let line = |request: Value| answer(request.to_string().as_bytes());
    let policy = line(json!({"op": "policy", "preset": "balanced"}));
    assert_eq!(policy["preset"], json!("balanced"));
    assert_eq!(
        policy["packDigest"],
        json!(shipped(Preset::Balanced).digest())
    );
    assert_eq!(
        policy["factRules"].as_array().map(Vec::len),
        Some(shipped(Preset::Balanced).fact_rules().len())
    );
    assert_eq!(
        line(json!({"op": "policy", "policyPack": balanced()}))["packDigest"],
        policy["packDigest"]
    );
    assert_eq!(
        line(json!({"op": "policy", "preset": "yolo"}))["error"]["code"],
        json!("preset_unknown")
    );
    let classified =
        line(json!({"op": "classify", "name": "deleteRepository", "preset": "strict"}));
    assert_eq!(classified["proposal"]["destructive"], json!(true));
    assert_eq!(classified["action"], json!("block"));
    assert_eq!(classified["facts"]["class"], json!("delete"));
    let plain = line(json!({"op": "classify", "name": "list_issues"}));
    assert!(plain.get("action").is_none());
    // An unknown tool is at least a write, and its facts claim nothing else.
    assert_eq!(plain["facts"]["class"], json!("update"));
    assert_eq!(plain["facts"]["schema"], json!("guard.action-facts.v2"));
    for key in ["object", "scope", "record_count", "money", "sensitivity"] {
        assert_eq!(plain["facts"][key], json!({"state": "unknown"}), "{key}");
    }
    // A class a workspace admin approved replaces the proposal in the facts only.
    let approved = line(json!({"op": "classify", "name": "deleteRepository", "class": "read"}));
    assert_eq!(approved["facts"]["class"], json!("read"));
    assert_eq!(approved["proposal"]["class"], json!("delete"));
    assert_eq!(
        line(json!({"op": "classify", "name": "x", "class": "erase"}))["error"]["code"],
        json!("request_invalid")
    );
    assert_eq!(
        line(json!({"op": "classify"}))["error"]["code"],
        json!("request_invalid")
    );
}
