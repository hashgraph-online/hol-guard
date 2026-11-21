//! `_codex_hook_artifacts`: one artifact per distinct unmanaged hook identity.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Map, Number, Value};

use super::codex_hooks::{Ownership, Record};
use super::codex_identity::IDENTITY_SCHEMA;
use super::codex_sources::ERR_VALUE;
use super::codex_value::HookVal;
use super::zcode_artifacts::{Fields, Scope};

const HARNESS: &str = "codex";

fn timeout_value(timeout: &HookVal) -> Result<Value, &'static str> {
    match timeout {
        HookVal::Int(digits) => digits
            .parse::<u64>()
            .map(Value::from)
            .or_else(|_| digits.parse::<i64>().map(Value::from))
            .map_err(|_| ERR_VALUE),
        HookVal::Float(number) => Number::from_f64(*number)
            .map(Value::Number)
            .ok_or(ERR_VALUE),
        _ => Err(ERR_VALUE),
    }
}

pub(super) fn hook_artifacts(records: &[Record]) -> Result<Vec<Value>, &'static str> {
    let mut by_identity: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for record in records {
        if record.ownership == Ownership::Unmanaged {
            by_identity
                .entry(&record.canonical_identity)
                .or_default()
                .push(record);
        }
    }
    let mut artifacts = Vec::new();
    for (identity, mut ordered) in by_identity {
        ordered.sort_by_cached_key(|record| {
            (
                record.source_path.clone(),
                record.source_format,
                record.coordinate(),
            )
        });
        let primary = ordered[0];
        let provenance: Vec<Value> = ordered
            .iter()
            .map(|record| {
                json!({
                    "path": record.source_path,
                    "format": record.source_format,
                    "coordinate": record.coordinate(),
                })
            })
            .collect();
        let formats: BTreeSet<&str> = ordered.iter().map(|record| record.source_format).collect();
        let paths: BTreeSet<&str> = ordered
            .iter()
            .map(|record| record.source_path.as_str())
            .collect();
        let timeout = match &primary.timeout {
            Some(timeout) => timeout_value(timeout)?,
            None => Value::Null,
        };
        let mut metadata = Map::new();
        metadata.insert(
            "codex_hook_identity_schema".to_owned(),
            json!(IDENTITY_SCHEMA),
        );
        metadata.insert("codex_hook_identity".to_owned(), json!(identity));
        metadata.insert("event".to_owned(), json!(primary.event_name));
        metadata.insert("matcher".to_owned(), json!(primary.matcher));
        metadata.insert("handler_type".to_owned(), json!(primary.handler_type));
        metadata.insert("timeout".to_owned(), timeout);
        metadata.insert("env_keys".to_owned(), json!(primary.environment_keys));
        metadata.insert("command_argv".to_owned(), json!(primary.command_argv));
        metadata.insert(
            "active".to_owned(),
            json!(primary.active && primary.source_hooks_enabled),
        );
        metadata.insert("executable".to_owned(), json!(primary.executable));
        metadata.insert("ownership".to_owned(), json!(["unmanaged"]));
        metadata.insert("source_provenance".to_owned(), Value::Array(provenance));
        metadata.insert("source_formats".to_owned(), json!(formats));
        metadata.insert("source_paths".to_owned(), json!(paths));
        let scope = Scope {
            harness: HARNESS,
            scope: &primary.source_scope,
        };
        artifacts.push(scope.wire(
            format!("{HARNESS}:{}:hook:{identity}", primary.source_scope),
            &primary.event_name,
            "hook",
            Path::new(&primary.source_path),
            Fields {
                command: primary.command.as_deref(),
                ..Fields::default()
            },
            metadata,
        ));
    }
    Ok(artifacts)
}
