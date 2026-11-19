use serde_json::{json, Value};

use super::{bundled, dispatch, Registry};

const SCHEMA: &str = "hol-guard.harness-protection-contracts.v1";

fn event() -> Value {
    json!({
        "event": "PreToolUse",
        "transport": "native_hook",
        "mode": "blocking",
        "declared_actions": ["observe", "block"],
        "error_behavior": "fails closed",
        "mandatory_compatibility": "honors the response",
        "known_blind_spots": [],
        "source_reference": "adapter.py",
    })
}

fn contract() -> Value {
    json!({
        "harness": "fixture",
        "install_aliases": ["fixture"],
        "config_paths": ["~/.fixture/config.json"],
        "event_surfaces": ["shell"],
        "native_approval": true,
        "browser_fallback": false,
        "resume_support": false,
        "known_blind_spots": "none",
        "smoke_command": "hol-guard install fixture --dry-run",
        "capability_events": [event()],
    })
}

fn with(mut base: Value, key: &str, value: Value) -> Value {
    base[key] = value;
    base
}

fn document(contracts: Vec<Value>) -> Value {
    json!({"schema": SCHEMA, "contracts": contracts})
}

#[test]
fn omitted_capability_fields_take_the_documented_defaults() {
    let registry = Registry::load(&document(vec![contract()])).expect("a valid document");
    let loaded = registry.contract("fixture").expect("the contract");
    let capability = &loaded["capability_events"][0];
    assert_eq!(capability["harness"], "fixture");
    assert_eq!(capability["adapter"], "fixture");
    assert_eq!(capability["host_version_scope"], "unknown");
    assert_eq!(capability["os_arch"], "unknown");
    assert_eq!(capability["local_hosted"], "local");
    assert_eq!(capability["tools"], json!([]));
    assert_eq!(capability["surface"], Value::Null);
    assert_eq!(loaded["surface_capabilities"], json!([]));
    assert_eq!(loaded["supported_actions"], json!([]));
    assert_eq!(loaded["docs_path"], Value::Null);
    assert_eq!(loaded["icon_label"], Value::Null);
}

#[test]
fn explicit_capability_fields_override_the_defaults() {
    let mut row = event();
    row["adapter"] = json!("fixture-cloud");
    row["host_version_scope"] = json!(">=2");
    row["os_arch"] = json!("linux-x64");
    row["local_hosted"] = json!("hosted");
    let registry = Registry::load(&document(vec![with(
        contract(),
        "capability_events",
        json!([row]),
    )]))
    .expect("a valid document");
    let capability = &registry.contract("fixture").expect("the contract")["capability_events"][0];
    assert_eq!(capability["adapter"], "fixture-cloud");
    assert_eq!(capability["host_version_scope"], ">=2");
    assert_eq!(capability["os_arch"], "linux-x64");
    assert_eq!(capability["local_hosted"], "hosted");
}

fn event_with(key: &str, value: Value) -> Value {
    with(
        contract(),
        "capability_events",
        json!([with(event(), key, value)]),
    )
}

#[test]
fn malformed_contract_data_is_refused() {
    let malformed = [
        json!([]),
        json!({"schema": "hol-guard.harness-protection-contracts.v2", "contracts": []}),
        json!({"schema": SCHEMA}),
        document(vec![json!("fixture")]),
        document(vec![with(contract(), "unexpected", json!(true))]),
        document(vec![with(contract(), "capability_events", json!([]))]),
        document(vec![event_with("unexpected", json!(true))]),
        document(vec![event_with("local_hosted", json!("remote"))]),
        document(vec![with(contract(), "native_approval", json!("yes"))]),
        document(vec![with(
            contract(),
            "install_aliases",
            json!(["fixture", 7]),
        )]),
        document(vec![with(contract(), "smoke_command", Value::Null)]),
        document(vec![with(contract(), "docs_path", json!(7))]),
        document(vec![with(contract(), "supported_actions", json!("block"))]),
        document(vec![event_with("declared_actions", json!("block"))]),
        // What the capability row itself used to refuse on construction.
        document(vec![event_with("transport", json!("  "))]),
        document(vec![event_with("adapter", Value::Null)]),
        document(vec![event_with("declared_actions", json!(["block", " "]))]),
        document(vec![event_with("declared_actions", json!(["launch"]))]),
        document(vec![event_with("known_blind_spots", json!([""]))]),
    ];
    for document in malformed {
        assert!(Registry::load(&document).is_none(), "{document}");
    }
}

#[test]
fn the_later_contract_answers_a_shared_name() {
    let mut other = contract();
    other["harness"] = json!("other");
    other["install_aliases"] = json!(["other", "fixture"]);
    let registry = Registry::load(&document(vec![contract(), other])).expect("a valid document");
    assert_eq!(
        registry.contract("fixture").expect("claimed")["harness"],
        "other"
    );
    assert!(registry.contract("missing").is_none());
}

#[test]
fn the_bundled_registry_loads_and_answers_every_op() {
    let registry = bundled().expect("the bundled contracts are valid");
    let all = dispatch(&json!({"op": "contracts"})).expect("contracts");
    let contracts = all["contracts"].as_array().expect("a list");
    assert_eq!(contracts.len(), 18);
    let names = dispatch(&json!({"op": "harnesses"})).expect("harnesses");
    assert_eq!(names["harnesses"].as_array().map(Vec::len), Some(18));
    let one = dispatch(&json!({"op": "contract", "harness": "claude-code"})).expect("contract");
    assert_eq!(one["contract"]["harness"], "claude-code");
    assert_eq!(registry.harnesses().len(), 18);
    let missing = dispatch(&json!({"op": "contract", "harness": "nonesuch"})).expect("contract");
    assert_eq!(missing["contract"], Value::Null);
}

#[test]
fn bad_requests_are_refused() {
    assert!(dispatch(&json!({"op": "nope"})).is_err());
    assert!(dispatch(&json!({"op": "contracts", "extra": 1})).is_err());
    assert!(dispatch(&json!({"op": "contract"})).is_err());
    assert!(dispatch(&json!({"op": "contract", "harness": 1})).is_err());
    assert!(dispatch(&json!(["contracts"])).is_err());
}
