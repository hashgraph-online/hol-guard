//! Parity tests for `inventory_contract`.
//!
//! The fixture is generated from the live Python
//! `codex_plugin_scanner.guard.inventory_contract`, so each case records what
//! the shipping implementation actually returns rather than what this port is
//! assumed to return. The module had no tests before, and nothing calls it yet,
//! so these cases are the only thing standing between a future cutover and a
//! silent change to the inventory wire contract.

use serde_json::{json, Map, Value};
use std::path::Path;

use crate::inventory_contract::{
    extract_aibom_metadata_extensions, AgentTypeApi, CiscoRun, FingerprintApi,
    GuardAgentInventoryFinding, GuardAgentInventoryItem, GuardInventorySource, InventoryDeps,
    InventoryRedactionApi, ItemProjectionApi, LocalArtifact, _normalize_inventory_datetime,
    _normalize_redaction_report, _snake_to_camel_case_key,
};

const PARITY: &str = include_str!("../testdata/inventory_contract_parity.json");

fn cases(name: &str) -> Vec<Map<String, Value>> {
    let doc: Value = serde_json::from_str(PARITY).expect("parity fixture parses");
    doc.get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("fixture has no {name} cases"))
        .iter()
        .map(|case| case.as_object().expect("each case is an object").clone())
        .collect()
}

/// `_safe_json` is the redaction module's own concern, exercised by its own
/// tests. These cases feed it values it passes through unchanged, so the stub
/// isolates the key selection and `sourceLinks` derivation that this module
/// actually owns. Every other seam panics: reaching one would mean the function
/// under test grew a dependency these cases do not describe.
struct PassthroughRedaction;

impl InventoryRedactionApi for PassthroughRedaction {
    fn redact_local_path(&self, _path: &Path, _home_dir: Option<&Path>) -> String {
        unreachable!("extract_aibom_metadata_extensions does not redact paths")
    }

    fn _redact_known_path(
        &self,
        _value: &str,
        _home_dir: &Path,
        _workspace_dir: Option<&Path>,
    ) -> String {
        unreachable!("extract_aibom_metadata_extensions does not redact paths")
    }

    fn _safe_finding_text(
        &self,
        _value: &str,
        _home_dir: &Path,
        _workspace_dir: Option<&Path>,
    ) -> String {
        unreachable!("extract_aibom_metadata_extensions reads no finding text")
    }

    fn _safe_source_detail(&self, _run: &Map<String, Value>) -> String {
        unreachable!("extract_aibom_metadata_extensions reads no source detail")
    }

    fn _safe_json(&self, value: &Value, _parent_key: &str, _parent_sensitive: bool) -> Value {
        value.clone()
    }

    fn _assert_serialized_inventory_payload_safe(&self, _payload: &Value) -> Result<(), String> {
        unreachable!("extract_aibom_metadata_extensions serializes no snapshot")
    }
}

struct UnusedFingerprint;

impl FingerprintApi for UnusedFingerprint {
    fn fingerprint_text(&self, _value: &str) -> String {
        unreachable!("no fingerprint is taken in these cases")
    }

    fn fingerprint_mapping(&self, _value: &Value) -> String {
        unreachable!("no fingerprint is taken in these cases")
    }

    fn inventory_item_id(
        &self,
        _agent_type: &str,
        _item_kind: &str,
        _display_name: &str,
        _semantic_text: &str,
    ) -> String {
        unreachable!("no item id is minted in these cases")
    }

    fn _inventory_snapshot_content_hash(
        &self,
        _agent_type: &str,
        _items: &[GuardAgentInventoryItem],
        _findings: &[GuardAgentInventoryFinding],
        _sources: &[GuardInventorySource],
        _runtime_version: Option<&str>,
    ) -> String {
        unreachable!("no snapshot is hashed in these cases")
    }
}

struct UnusedAgentType;

impl AgentTypeApi for UnusedAgentType {
    fn _agent_type(&self, _agent_id: &str) -> String {
        unreachable!("no agent type is resolved in these cases")
    }
}

struct UnusedItems;

impl ItemProjectionApi for UnusedItems {
    #[allow(clippy::too_many_arguments)]
    fn _item_from_artifact(
        &self,
        _harness: &str,
        _artifact: &LocalArtifact,
        _generated_at: &str,
        _home_dir: &Path,
        _workspace_dir: Option<&Path>,
        _cisco_runs: &[CiscoRun],
        _include_symlinks: bool,
        _follow_unsafe_symlinks: bool,
        _trust_attestation_context: Option<&Map<String, Value>>,
    ) -> GuardAgentInventoryItem {
        unreachable!("no artifact is projected in these cases")
    }

    #[allow(clippy::too_many_arguments)]
    fn _mcp_tool_items_from_artifact(
        &self,
        _harness: &str,
        _artifact: &LocalArtifact,
        _item: &GuardAgentInventoryItem,
        _generated_at: &str,
        _home_dir: &Path,
        _workspace_dir: Option<&Path>,
        _cisco_runs: &[CiscoRun],
        _trust_attestation_context: Option<&Map<String, Value>>,
    ) -> Vec<GuardAgentInventoryItem> {
        unreachable!("no MCP tool items are projected in these cases")
    }

    fn discover_shared_workspace_aibom_artifacts(
        &self,
        _harness: &str,
        _home_dir: &Path,
        _workspace_dir: &Path,
    ) -> Vec<LocalArtifact> {
        unreachable!("no workspace discovery happens in these cases")
    }
}

#[test]
fn snake_to_camel_case_key_matches_python() {
    for case in cases("snake_to_camel_case_key") {
        let key = case["key"].as_str().expect("key is a string");
        let expected = case["expected"].as_str().expect("expected is a string");
        assert_eq!(
            _snake_to_camel_case_key(key),
            expected,
            "key {key:?} translated differently from Python"
        );
    }
}

#[test]
fn snake_to_camel_case_key_keeps_empty_segments() {
    // `"a__b"` splits to `["a", "", "b"]`; Python's generator emits nothing for
    // the empty part rather than panicking on `part[:1]`, so the underscore
    // simply disappears. Indexing a Rust `&str` at 0..1 would not.
    assert_eq!(_snake_to_camel_case_key("a__b"), "aB");
    assert_eq!(_snake_to_camel_case_key("a_"), "a");
    assert_eq!(_snake_to_camel_case_key("_a"), "A");
}

#[test]
fn normalize_redaction_report_matches_python() {
    for case in cases("normalize_redaction_report") {
        let report = &case["report"];
        let expected = case["expected"].as_object().expect("expected is an object");
        assert_eq!(
            &_normalize_redaction_report(report),
            expected,
            "report {report} normalized differently from Python"
        );
    }
}

#[test]
fn normalize_redaction_report_only_accepts_literal_true() {
    // Python compares with `is True`, so a truthy non-boolean stays false. A
    // Rust port reaching for truthiness here would leak raw secrets past the
    // flag that is supposed to announce them.
    let truthy = json!({"rawSecretsIncluded": "yes"});
    assert_eq!(
        _normalize_redaction_report(&truthy)["rawSecretsIncluded"],
        json!(false)
    );
}

#[test]
fn normalize_inventory_datetime_matches_python() {
    for case in cases("normalize_inventory_datetime") {
        let value = &case["value"];
        assert_eq!(
            &_normalize_inventory_datetime(value),
            &case["expected"],
            "timestamp {value} normalized differently from Python"
        );
    }
}

#[test]
fn normalize_inventory_datetime_converts_to_utc() {
    // The offset form is the one that would silently shift an inventory record
    // by hours if the port dropped the conversion and kept the wall clock.
    assert_eq!(
        _normalize_inventory_datetime(&json!("2026-10-21T08:24:55-05:00")),
        json!("2026-10-21T13:24:55Z")
    );
    assert_eq!(
        _normalize_inventory_datetime(&json!("not-a-date")),
        json!("not-a-date")
    );
}

#[test]
fn extract_aibom_metadata_extensions_matches_python() {
    let redaction = PassthroughRedaction;
    let fingerprint = UnusedFingerprint;
    let agent_type = UnusedAgentType;
    let items = UnusedItems;
    let deps = InventoryDeps {
        redaction: &redaction,
        fingerprint: &fingerprint,
        agent_type: &agent_type,
        items: &items,
    };
    for case in cases("extract_aibom_metadata_extensions") {
        let metadata = case["metadata"]
            .as_object()
            .expect("metadata is an object")
            .clone();
        let expected = case["expected"].as_object().expect("expected is an object");
        assert_eq!(
            &extract_aibom_metadata_extensions(&metadata, &deps),
            expected,
            "metadata {:?} projected differently from Python",
            case["metadata"]
        );
    }
}

#[test]
fn extract_aibom_metadata_extensions_keeps_an_explicit_source_links() {
    // `sourceLinks` is derived from `sourceOfTruth` only when it is absent.
    // Deriving it unconditionally would overwrite a caller's own list.
    let redaction = PassthroughRedaction;
    let fingerprint = UnusedFingerprint;
    let agent_type = UnusedAgentType;
    let items = UnusedItems;
    let deps = InventoryDeps {
        redaction: &redaction,
        fingerprint: &fingerprint,
        agent_type: &agent_type,
        items: &items,
    };
    let metadata = json!({
        "sourceOfTruth": {"url": "https://example.test/a"},
        "sourceLinks": ["kept"],
    })
    .as_object()
    .expect("object")
    .clone();
    let extensions = extract_aibom_metadata_extensions(&metadata, &deps);
    assert_eq!(extensions["sourceLinks"], json!(["kept"]));
}
