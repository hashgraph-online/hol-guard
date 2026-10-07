//! Byte-exact ports of the install-time event payload composer and the dict
//! coercion helper from `local_supply_chain.py` (RTM-019).
//!
//! - `install_time_event_payload` ↔ `_install_time_event_payload`
//!   (local_supply_chain.py:1972-1989): composes the audit event dict stored
//!   via `store.add_event(f"install_time_{action}", ...)` / the
//!   `install_time_execution_failed` variants. `**extra` fields append after
//!   the seven fixed keys and override earlier keys on collision.
//! - `dict_payload` ↔ `_dict_payload` (local_supply_chain.py:4640-4641):
//!   dict-coerce — returns the value when it is a mapping, `{}` otherwise.
//!
//! NOTE — harness constant: the Python constant is
//! `runtime.package_protect_projection.LOCAL_SUPPLY_CHAIN_HARNESS =
//! "guard-cli"` (imported as `_LOCAL_SUPPLY_CHAIN_HARNESS`,
//! local_supply_chain.py:74). The pre-existing Rust constant
//! `crate::local_supply_chain::LOCAL_SUPPLY_CHAIN_HARNESS` is
//! `"local-supply-chain"`, which does NOT match the oracle — see the module
//! owner's parity note; this file uses the oracle value `"guard-cli"`.

use serde_json::{json, Map, Value};

use crate::effect_decision::GuardAction;
use crate::local_supply_chain::PackageProtectAuthority;

/// `_LOCAL_SUPPLY_CHAIN_HARNESS` — `runtime.package_protect_projection`
/// (:14): `"guard-cli"`. Distinct from the divergent
/// `local_supply_chain::LOCAL_SUPPLY_CHAIN_HARNESS` constant.
pub const LOCAL_SUPPLY_CHAIN_HARNESS: &str = "guard-cli";

/// `_install_time_event_payload` (:1972-1989).
///
/// Composes `{"artifact_id", "artifact_name", "executor", "harness",
/// "install_kind", "action", "risk_signals", **extra}`. `executor` is
/// `str(command[0])` when `command` is non-empty, else the harness constant.
/// `extra` pairs are appended in order after the fixed keys; a key colliding
/// with a fixed key replaces that key's value while keeping its slot, exactly
/// matching Python `dict` literal + `**extra` unpacking semantics.
///
/// `serde_json::Map` is a `BTreeMap`: iteration/serialization is sorted-key
/// order rather than Python's insertion order, but the key set, value types,
/// and override semantics are identical, and canonical JSON bytes are
/// byte-exact against `json.dumps(..., sort_keys=True, ensure_ascii=True)`.
pub fn install_time_event_payload(
    authority: &PackageProtectAuthority,
    command: &[String],
    action: GuardAction,
    risk_signals: &[String],
    extra: impl IntoIterator<Item = (String, Value)>,
) -> Value {
    let mut payload = Map::new();
    payload.insert(
        "artifact_id".to_owned(),
        json!(authority.artifact.artifact_id),
    );
    payload.insert("artifact_name".to_owned(), json!(authority.artifact.name));
    payload.insert(
        "executor".to_owned(),
        json!(command
            .first()
            .map(String::as_str)
            .unwrap_or(LOCAL_SUPPLY_CHAIN_HARNESS)),
    );
    payload.insert("harness".to_owned(), json!(authority.invoking_harness));
    payload.insert(
        "install_kind".to_owned(),
        json!(authority.intent.intent_kind),
    );
    payload.insert("action".to_owned(), json!(action.as_str()));
    payload.insert("risk_signals".to_owned(), json!(risk_signals));
    for (key, value) in extra {
        payload.insert(key, value);
    }
    Value::Object(payload)
}

/// `_dict_payload` (:4640-4641): dict-coerce — the value itself when it is a
/// mapping, `{}` otherwise. Unlike the pre-existing `local_supply_chain.rs`
/// helper of the same name (which returns `Option<Map>`), this mirrors the
/// Python signature exactly: it always returns a dict.
pub fn dict_payload(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::local_supply_chain::PackageRequestEvaluation;
    use crate::package_execution_context::PackageExecutionContext;
    use crate::package_intent_common::{GuardArtifact, PackageIntent, PackageIntentTarget};

    fn artifact() -> GuardArtifact {
        GuardArtifact {
            artifact_id: "art-1".to_string(),
            name: "lodash-pkg".to_string(),
            harness: "guard-cli".to_string(),
            artifact_type: "package-request".to_string(),
            source_scope: "workspace".to_string(),
            config_path: "/tmp/proj/.holguard".to_string(),
            command: None,
            args: vec![],
            url: None,
            transport: None,
            publisher: None,
            metadata: json!({}),
            runtime_private_metadata: json!({}),
        }
    }

    fn intent() -> PackageIntent {
        PackageIntent {
            package_manager: "npm".to_string(),
            intent_kind: "install",
            command_tokens: vec!["npm".into(), "install".into(), "lodash".into()],
            redacted_command: "npm install lodash".into(),
            targets: vec![PackageIntentTarget {
                ecosystem: "npm".into(),
                package_name: Some("lodash".into()),
                raw_spec: "lodash@4.17.21".into(),
                requested_specifier: Some("^4.0.0".into()),
                source_url: None,
                source_kind: None,
                source_repository: None,
                source_revision_kind: None,
                source_identity: None,
                source_invalid_reason: None,
                alias: None,
                dependency_group: None,
                extras: vec![],
                editable: false,
            }],
            manifest_paths: vec![],
            lockfile_paths: vec![],
            flags: vec![],
            notes: vec![],
            local_executions: vec![],
            execution_context_hashes: vec![],
            execution_context_cwds: vec![],
            execution_context_reason_codes: vec![],
        }
    }

    fn authority() -> PackageProtectAuthority {
        PackageProtectAuthority {
            intent: intent(),
            artifact: artifact(),
            evaluation: PackageRequestEvaluation::default(),
            current_action: None,
            execution_context: PackageExecutionContext {
                digest: "d".repeat(64),
                portable: false,
                components: vec![],
                non_portable_reason: None,
            },
            artifact_hash: "a".repeat(64),
            launch_identity: Value::Null,
            launch_cwd: PathBuf::from("/tmp/proj"),
            launch_environment: BTreeMap::new(),
            additional_current_action: None,
            additional_policy_context: None,
            observe_mode: false,
            invoking_harness: "claude-code".to_string(),
        }
    }

    fn canonical_json(value: &Value) -> String {
        let mut buf = Vec::new();
        guard_contracts::write_canonical_json(value, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn install_time_event_payload_minimal_exact_oracle_bytes() {
        let payload = install_time_event_payload(
            &authority(),
            &["npm".into(), "install".into(), "lodash".into()],
            GuardAction::RequireReapproval,
            &["sig-1".into(), "sig-2".into()],
            Vec::new(),
        );
        assert_eq!(
            canonical_json(&payload),
            concat!(
                r#"{"action":"require-reapproval","artifact_id":"art-1","artifact_name":"lodash-pkg","#,
                r#""executor":"npm","harness":"claude-code","install_kind":"install","#,
                r#""risk_signals":["sig-1","sig-2"]}"#,
            )
        );
    }

    #[test]
    fn install_time_event_payload_empty_command_uses_guard_cli_harness() {
        let payload = install_time_event_payload(
            &authority(),
            &[],
            GuardAction::Block,
            &[],
            vec![("error".to_string(), json!("TimeoutExpired"))],
        );
        assert_eq!(
            canonical_json(&payload),
            concat!(
                r#"{"action":"block","artifact_id":"art-1","artifact_name":"lodash-pkg","#,
                r#""error":"TimeoutExpired","executor":"guard-cli","harness":"claude-code","#,
                r#""install_kind":"install","risk_signals":[]}"#,
            )
        );
    }

    #[test]
    fn install_time_event_payload_extra_overrides_fixed_key() {
        // Python `**extra` overrides the fixed `artifact_id` key while keeping
        // its position; the override is observable in the canonical bytes.
        let payload = install_time_event_payload(
            &authority(),
            &["npm".into()],
            GuardAction::Allow,
            &["sig-µ".into()],
            vec![
                ("artifact_id".to_string(), json!("OVERRIDE")),
                ("note".to_string(), Value::Null),
            ],
        );
        assert_eq!(
            canonical_json(&payload),
            concat!(
                r#"{"action":"allow","artifact_id":"OVERRIDE","artifact_name":"lodash-pkg","#,
                r#""executor":"npm","harness":"claude-code","install_kind":"install","#,
                r#""note":null,"risk_signals":["sig-\u00b5"]}"#,
            )
        );
    }

    #[test]
    fn install_time_event_payload_returncode_extra_exact_oracle_bytes() {
        let payload = install_time_event_payload(
            &authority(),
            &["pip".into(), "install".into()],
            GuardAction::Warn,
            &["r1".into()],
            vec![("returncode".to_string(), json!(1))],
        );
        assert_eq!(
            canonical_json(&payload),
            concat!(
                r#"{"action":"warn","artifact_id":"art-1","artifact_name":"lodash-pkg","#,
                r#""executor":"pip","harness":"claude-code","install_kind":"install","#,
                r#""returncode":1,"risk_signals":["r1"]}"#,
            )
        );
    }

    #[test]
    fn install_time_event_payload_key_set_and_types() {
        let command = vec![
            "npm".to_string(),
            "install".to_string(),
            "lodash".to_string(),
        ];
        let signals = vec!["sig-1".to_string(), "sig-2".to_string()];
        let payload = install_time_event_payload(
            &authority(),
            &command,
            GuardAction::RequireReapproval,
            &signals,
            Vec::new(),
        );
        let object = payload.as_object().unwrap();
        let keys: Vec<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "action",
                "artifact_id",
                "artifact_name",
                "executor",
                "harness",
                "install_kind",
                "risk_signals",
            ]
        );
        assert_eq!(object["artifact_id"], json!("art-1"));
        assert_eq!(object["artifact_name"], json!("lodash-pkg"));
        assert_eq!(object["executor"], json!("npm"));
        assert_eq!(object["harness"], json!("claude-code"));
        assert_eq!(object["install_kind"], json!("install"));
        assert_eq!(object["action"], json!("require-reapproval"));
        assert_eq!(object["risk_signals"], json!(["sig-1", "sig-2"]));
    }

    #[test]
    fn dict_payload_returns_map_for_object() {
        let value = json!({"a": 1, "b": [1, 2]});
        let coerced = dict_payload(&value);
        assert_eq!(coerced.len(), 2);
        assert_eq!(coerced["a"], json!(1));
        assert_eq!(coerced["b"], json!([1, 2]));
    }

    #[test]
    fn dict_payload_non_dict_coerces_to_empty() {
        // Python `isinstance(value, dict)` rejects every non-mapping.
        for value in [
            json!("str"),
            Value::Null,
            json!([1, 2]),
            json!(7),
            json!(true),
            json!(-0.5),
        ] {
            assert!(dict_payload(&value).is_empty(), "value {value:?}");
        }
    }

    #[test]
    fn dict_payload_empty_object_returns_empty_map() {
        assert!(dict_payload(&json!({})).is_empty());
    }
}
