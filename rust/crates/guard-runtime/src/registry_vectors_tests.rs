//! Replay of the shared registry range-resolution vectors.
//!
//! `tests/fixtures/supply-chain-eval/registry-cases.v1.json` was recorded from
//! the Python resolver (see `record_registry_vectors.py` and the file's
//! `recorded_from_commit`). Each case runs the resident resolver against a fake
//! registry that returns the recorded upstream response, and requires the same
//! metadata request (URL and headers) and the same resolved version Python
//! produced.

use std::cell::RefCell;
use std::path::Path;

use guard_command::supply_chain_package_eval::{
    resolve_registry_target_version, RegistryDocument, RegistryMetadataApi,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::ResidentEvalDeps;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/supply-chain-eval/registry-cases.v1.json"
));

struct FakeRegistry {
    response: Value,
    seen: RefCell<Vec<(String, String)>>,
}

impl RegistryMetadataApi for FakeRegistry {
    fn fetch_registry_metadata(&self, url: &str, accept: &str) -> Option<RegistryDocument> {
        self.seen
            .borrow_mut()
            .push((url.to_owned(), accept.to_owned()));
        match self.response["kind"].as_str() {
            Some("payload") => self.response["payload"].as_object().cloned().map(|object| {
                let version_order = object
                    .get("versions")
                    .and_then(Value::as_object)
                    .map(|versions| versions.keys().cloned().collect())
                    .unwrap_or_default();
                RegistryDocument {
                    object,
                    version_order,
                }
            }),
            _ => None,
        }
    }
}

fn resolve(
    target: &Map<String, Value>,
    range: &str,
    response: Value,
) -> (Option<String>, Vec<(String, String)>) {
    let holder = ResidentEvalDeps::new(
        Path::new("/nonexistent/guard.db"),
        Path::new("/nonexistent"),
    );
    let fake = FakeRegistry {
        response,
        seen: RefCell::default(),
    };
    let mut deps = holder.as_deps();
    deps.registry = &fake;
    let resolved = resolve_registry_target_version(&deps, target, range);
    let seen = fake.seen.borrow().clone();
    (resolved, seen)
}

#[test]
fn registry_resolution_matches_recorded_python_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("registry vectors parse");
    assert_eq!(vectors["schema"], "guard-supply-chain-registry-vectors.v1");
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 40, "vector set must stay substantial");
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let target = case["target"].as_object().expect("target");
        let range = case["range"].as_str().expect("range");
        let (resolved, seen) = resolve(target, range, case["response"].clone());
        let expected_requests: Vec<(String, String)> = case["requests"]
            .as_array()
            .expect("requests")
            .iter()
            .map(|request| {
                assert_eq!(request["user_agent"], "hol-guard-local", "{name}");
                assert_eq!(request["timeout_seconds"], 1, "{name}");
                (
                    request["url"].as_str().expect("url").to_owned(),
                    request["accept"].as_str().expect("accept").to_owned(),
                )
            })
            .collect();
        assert_eq!(seen, expected_requests, "{name}: registry request");
        assert_eq!(
            resolved.as_deref(),
            case["expect"].as_str(),
            "{name}: resolved version"
        );
    }
}

#[test]
fn registry_override_fixture_is_used_without_the_network() {
    let holder = ResidentEvalDeps::new(
        Path::new("/nonexistent/guard.db"),
        Path::new("/nonexistent"),
    )
    .with_registry_metadata_override(
        json!({"https://registry.npmjs.org/left-pad": {"versions": {"1.2.3": {}}}})
            .as_object()
            .cloned(),
    );
    let deps = holder.as_deps();
    let target = json!({"name": "left-pad", "ecosystem": "npm"});
    let target = target.as_object().expect("object");
    assert_eq!(
        resolve_registry_target_version(&deps, target, "^1.0.0").as_deref(),
        Some("1.2.3")
    );
    let other = json!({"name": "other", "ecosystem": "npm"});
    assert_eq!(
        resolve_registry_target_version(&deps, other.as_object().expect("object"), "^1.0.0"),
        None,
        "an absent fixture is unresolved, never a network fetch"
    );
}
