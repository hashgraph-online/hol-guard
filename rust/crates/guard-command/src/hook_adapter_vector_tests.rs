//! Replays vectors recorded from the pre-port Python implementation.

use std::path::Path;

use crate::hook_adapter_envelope::{normalize_harness_envelope, EnvelopeRequest, IntentSummary};
use crate::hook_adapter_paths::PathEnv;
use crate::hook_adapter_prepare::{prepare_payload, AdapterError};
use crate::hook_adapter_value::{parse_python_json, OMap, OValue};

const VECTORS: &str = include_str!("../testdata/hook_adapter_vectors.json");

fn vectors() -> OMap {
    match parse_python_json(VECTORS) {
        Ok(OValue::Map(map)) => map,
        _ => panic!("vectors must parse"),
    }
}

fn list<'a>(map: &'a OMap, key: &str) -> &'a [OValue] {
    map.get(key).and_then(OValue::as_list).expect("vector list")
}

fn field<'a>(map: &'a OMap, key: &str) -> &'a OValue {
    map.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

pub(crate) fn expected_error(expected: &OMap) -> Option<(String, String)> {
    let error = expected.get("error")?.as_map()?;
    Some((
        error.get_str("kind")?.to_owned(),
        error.get_str("message")?.to_owned(),
    ))
}

pub(crate) fn error_parts(error: &AdapterError) -> (String, String) {
    match error {
        AdapterError::ClinePayload(message) => ("cline_payload".to_owned(), message.clone()),
        AdapterError::UnsupportedHarness(harness) => (
            "unsupported_harness".to_owned(),
            format!("Unsupported Guard harness for action normalization: {harness}"),
        ),
        AdapterError::Unsupported(code) => ("unsupported".to_owned(), (*code).to_owned()),
    }
}

#[test]
fn prepare_vectors_match_recorded_python() {
    let root = vectors();
    let mut failures = Vec::new();
    assert!(list(&root, "prepare").len() >= 900);
    for vector in list(&root, "prepare") {
        let vector = vector.as_map().expect("vector map");
        let name = vector.get_str("name").unwrap_or("?");
        let harness = vector.get_str("harness").unwrap_or("");
        let payload = field(vector, "payload").as_map().expect("payload map");
        let project_dir = vector.get_str("devin_project_dir");
        let expected = field(vector, "expected").as_map().expect("expected map");
        let actual = prepare_payload(harness, payload, project_dir);
        let matches = match (&actual, expected.get("ok"), expected_error(expected)) {
            (Ok(actual), Some(OValue::Map(want)), _) => actual == want,
            (Err(error), _, Some(want)) => error_parts(error) == want,
            _ => false,
        };
        if !matches {
            failures.push(format!("{name}: {actual:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} prepare vectors differ; first: {}",
        failures.len(),
        failures
            .first()
            .map_or("", String::as_str)
            .chars()
            .take(1200)
            .collect::<String>()
    );
}

fn stub_provider(
    calls: &[OValue],
) -> impl FnMut(&str, Option<&Path>, Option<&Path>) -> Option<IntentSummary> + '_ {
    move |command, workspace, home| {
        let call = calls.iter().filter_map(OValue::as_map).find(|call| {
            call.get_str("command") == Some(command)
                && call.get_str("workspace") == workspace.and_then(Path::to_str)
                && call.get_str("home_dir") == home.and_then(Path::to_str)
        });
        let Some(call) = call else {
            panic!("unrecorded package intent call for {command:?}");
        };
        let result = call.get("result")?.as_map()?;
        let targets = result
            .get("targets")?
            .as_list()?
            .iter()
            .filter_map(OValue::as_map)
            .map(|target| {
                (
                    target.get_str("raw_spec").unwrap_or("").to_owned(),
                    target.get_str("package_name").map(str::to_owned),
                )
            })
            .collect();
        Some(IntentSummary {
            package_manager: result.get_str("package_manager")?.to_owned(),
            intent_kind: result.get_str("intent_kind")?.to_owned(),
            targets,
        })
    }
}

#[test]
fn envelope_vectors_match_recorded_python() {
    let root = vectors();
    let mut failures = Vec::new();
    assert!(list(&root, "envelope").len() >= 1500);
    for vector in list(&root, "envelope") {
        let vector = vector.as_map().expect("vector map");
        let name = vector.get_str("name").unwrap_or("?");
        let payload = field(vector, "payload").as_map().expect("payload map");
        let calls = list(vector, "stub_calls");
        let request = EnvelopeRequest {
            harness: vector.get_str("harness").unwrap_or(""),
            event_name: vector.get_str("event_name").unwrap_or(""),
            payload,
            workspace: vector.get_str("workspace"),
            home_dir: vector.get_str("home_dir"),
            devin_project_dir: None,
            env: PathEnv::default(),
        };
        let expected = field(vector, "expected").as_map().expect("expected map");
        let mut provider = stub_provider(calls);
        let actual = normalize_harness_envelope(&request, &mut provider);
        let matches = match (&actual, expected.get("ok"), expected_error(expected)) {
            (Ok(actual), Some(OValue::Map(want)), _) => actual == want,
            (Err(error), _, Some(want)) => error_parts(error) == want,
            _ => false,
        };
        if !matches {
            let diff = match (&actual, expected.get("ok")) {
                (Ok(actual), Some(OValue::Map(want))) => actual
                    .iter()
                    .filter(|(key, value)| want.get(key) != Some(value))
                    .map(|(key, value)| format!("{key}: got {value:?} want {:?}", want.get(key)))
                    .collect::<Vec<_>>()
                    .join("; "),
                _ => format!("{actual:?}"),
            };
            failures.push(format!("{name}: {diff}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} envelope vectors differ; first: {}",
        failures.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .take(3000)
            .collect::<String>()
    );
}
