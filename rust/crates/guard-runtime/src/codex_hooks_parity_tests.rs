//! Replays `tests/fixtures/codex-hook-inventory.v1.json`, recorded from
//! `codex_hook_inventory.py`. The CLI install path reads that Python inventory
//! and detection reads this one, so the shapes each refuses, the coordinates it
//! names and the repair wording it uses have to stay identical on both routes.
//!
//! The fixture pins the issues each shape produces and, for every record the
//! walk keeps, its coordinate and the two flags that decide whether the hook
//! runs. It records no identity: a record carries the identity the resident
//! derives for it, which no fixture can replay, while the shape walk that
//! produces these coordinates is ordinary code on both sides.

use serde_json::Value;

use crate::codex_hooks::{enumerate, Source};
use crate::codex_value::HookVal;
use crate::pyjson::{self, PyVal};

const FIXTURE: &str = include_str!("../../../../tests/fixtures/codex-hook-inventory.v1.json");

fn field<'a>(value: &'a PyVal, key: &str) -> &'a PyVal {
    let PyVal::Dict(entries) = value else {
        panic!("{key} is not held by an object");
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == key)
        .map(|(_, held)| held)
        .unwrap_or_else(|| panic!("the fixture records no {key}"))
}

/// The payloads, in the order the fixture spells them.
///
/// A hook file lists its events in whatever order its author wrote them, and
/// the walk reports records back in that same order. `serde_json` is built
/// here without `preserve_order`, so reading a payload back out of a parsed
/// [`Value`] would sort the events and pin an order no config file has to
/// use. Reading the fixture through the runtime's own parser — the one the
/// hook files themselves go through — keeps each case as it was recorded.
fn recorded_payloads() -> Vec<HookVal> {
    let document = pyjson::parse(FIXTURE).expect("fixture parses as python json");
    let PyVal::List(cases) = field(&document, "cases") else {
        panic!("the fixture records no case list");
    };
    cases
        .iter()
        .map(|case| HookVal::from_py(field(case, "payload")))
        .collect()
}

fn format_of(name: &str) -> &'static str {
    match name {
        "json" => "json",
        "toml" => "toml",
        other => panic!("unsupported source format {other}"),
    }
}

fn bindings(case: &Value, key: &str) -> Vec<Value> {
    case[key].as_array().expect("bindings array").clone()
}

#[test]
fn recorded_shape_issues_still_describe_the_source() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    assert_eq!(document["schema"], "codex-hook-inventory-parity.v1");
    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the fixture records no cases");
    let payloads = recorded_payloads();
    assert_eq!(payloads.len(), cases.len(), "every case records a payload");
    for (case, payload) in cases.iter().zip(&payloads) {
        let name = case["name"].as_str().expect("name");
        let source = &case["source"];
        let authenticated = bindings(case, "authenticated");
        let legacy = bindings(case, "legacy");
        let inventory = enumerate(
            payload,
            Source {
                path: source["path"].as_str().expect("path"),
                scope: source["scope"].as_str().expect("scope"),
                format: format_of(source["format"].as_str().expect("format")),
                hooks_enabled: source["hooks_enabled"].as_bool().expect("hooks_enabled"),
            },
            &authenticated,
            &legacy,
        );
        let expected: Vec<&str> = case["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .map(|warning| warning.as_str().expect("warning"))
            .collect();
        assert_eq!(inventory.warnings, expected, "{name}");

        let recorded: Vec<Value> = inventory
            .records
            .iter()
            .map(|record| {
                serde_json::json!({
                    "coordinate": record.coordinate(),
                    "active": record.active,
                    "executable": record.executable,
                })
            })
            .collect();
        let expected_records = case["records"].as_array().expect("records");
        assert_eq!(&recorded, expected_records, "{name}");
    }
}
