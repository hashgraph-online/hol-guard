//! `GET /v1/plugins/updates`, answered as `plugin_updates_http` answers it:
//! the two public HOL indexes are downloaded under the machine's managed
//! network policy, cut down to the repositories installed here, and compared
//! with the installed plugins on the device by the plugin-telemetry runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use guard_command::egress_caller::policy_get;
use serde_json::{json, Map, Value};

use super::ReadConfig;
use crate::managed_policy_load::ManagedPolicySource;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;

/// `report.INDEX_URL`.
const INDEX_URL: &str = "https://hol.org/api/guard/plugins/install-telemetry/index";
/// `updates.RELEASE_INDEX_URL`.
const RELEASE_INDEX_URL: &str = "https://hol.org/api/guard/plugins/releases/index";
/// `_INDEX_TIMEOUT_SECONDS`: HOL can take about 30 seconds to build the index.
const INDEX_TIMEOUT_SECONDS: f64 = 60.0;
/// `_INDEX_LIMIT_BYTES`.
const INDEX_LIMIT_BYTES: u64 = 32 * 1024 * 1024;
/// `_NATIVE_REQUEST_LIMIT_BYTES`.
const NATIVE_REQUEST_LIMIT_BYTES: usize = 6 * 1024 * 1024;
/// urllib's `HTTPRedirectHandler.max_redirections`.
const MAX_REDIRECTS: u32 = 10;
/// `_INDEX_FIELDS`.
const INDEX_FIELDS: [&str; 4] = ["slug", "repository", "manifestName", "pluginRoot"];

/// The two indexes' names as the daemon's messages give them.
#[derive(Clone, Copy)]
enum Index {
    Plugin,
    Release,
}

impl Index {
    fn url(self) -> &'static str {
        match self {
            Self::Plugin => INDEX_URL,
            Self::Release => RELEASE_INDEX_URL,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Plugin => "plugin",
            Self::Release => "release",
        }
    }
}

/// The route's answer, or `None` when the daemon names no user home to find
/// the agent runtimes under.
pub(in crate::daemon_edge) fn read(config: &ReadConfig) -> Option<(u16, Value)> {
    let home = config.user_home.as_deref()?;
    Some(match check_updates(Path::new(home), &config.guard_home) {
        Ok(result) => (200, result),
        Err(message) => (
            503,
            json!({"error": "plugin_updates_unavailable", "message": message}),
        ),
    })
}

/// `updates.check_updates`.
fn check_updates(home: &Path, guard_home: &str) -> Result<Value, String> {
    let homes = runtime_homes(home);
    let index = installed_index(plugin_index()?, &homes)?;
    let slugs: BTreeSet<&str> = index
        .iter()
        .filter_map(|entry| entry.get("slug").and_then(Value::as_str))
        .collect();
    let releases: Vec<Value> = entries(Index::Release)?
        .into_iter()
        .filter(|entry| {
            entry
                .get("slug")
                .and_then(Value::as_str)
                .is_some_and(|slug| slugs.contains(slug))
        })
        .collect();
    native_request(&json!({
        "command": "updates",
        "homes": homes,
        "index": index,
        "releases": releases,
        "guardHome": guard_home,
    }))
}

/// `report.runtime_homes`: the agent runtime homes that exist here.
pub(in crate::daemon_edge) fn runtime_homes(home: &Path) -> Map<String, Value> {
    let configured = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let candidates = [
        (
            "claude",
            configured("CLAUDE_CONFIG_DIR")
                .unwrap_or_else(|| home.join(".claude").to_string_lossy().into_owned()),
        ),
        (
            "codex",
            configured("CODEX_HOME")
                .unwrap_or_else(|| home.join(".codex").to_string_lossy().into_owned()),
        ),
        (
            "gemini",
            home.join(".gemini").to_string_lossy().into_owned(),
        ),
        (
            "cursor",
            home.join(".cursor").to_string_lossy().into_owned(),
        ),
    ];
    candidates
        .into_iter()
        .filter(|(_, path)| Path::new(path).is_dir())
        .map(|(name, path)| (name.to_owned(), Value::String(path)))
        .collect()
}

/// `report.fetch_index`: each listing keeps only its string index fields.
fn plugin_index() -> Result<Vec<Value>, String> {
    Ok(entries(Index::Plugin)?
        .into_iter()
        .filter(|entry| entry.get("slug").is_some_and(Value::is_string))
        .map(|entry| {
            let kept: Map<String, Value> = INDEX_FIELDS
                .iter()
                .filter_map(|field| {
                    entry
                        .get(*field)
                        .filter(|value| value.is_string())
                        .map(|value| ((*field).to_owned(), value.clone()))
                })
                .collect();
            Value::Object(kept)
        })
        .collect())
}

/// The object entries of one index's `entries` list.
fn entries(index: Index) -> Result<Vec<Value>, String> {
    let name = index.name();
    let raw = download(index.url()).map_err(|large| match large {
        true => format!("The HOL {name} index is larger than expected."),
        false => format!("The HOL {name} index could not be downloaded."),
    })?;
    entries_from(&raw).map_err(|parsed| match parsed {
        false => format!("The HOL {name} index was not valid JSON."),
        true => format!("The HOL {name} index was not in the expected shape."),
    })
}

/// The object entries of a downloaded index; `Err(parsed)` says whether the
/// body was JSON at all.
pub(in crate::daemon_edge) fn entries_from(raw: &[u8]) -> Result<Vec<Value>, bool> {
    let payload: Value = serde_json::from_slice(raw).map_err(|_| false)?;
    match payload.get("entries") {
        Some(Value::Array(items)) => Ok(items
            .iter()
            .filter(|item| item.is_object())
            .cloned()
            .collect()),
        _ => Err(true),
    }
}

/// One index body under the managed network policy. `Err(true)` is a body
/// over the cap; `Err(false)` any other failure, a non-2xx status included.
fn download(url: &str) -> Result<Vec<u8>, bool> {
    let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
        .map_err(|_| false)?;
    let headers = BTreeMap::from([
        ("User-Agent".to_owned(), crate::daemon_edge::user_agent()),
        ("Accept".to_owned(), "application/json".to_owned()),
    ]);
    match policy_get(
        url,
        headers,
        INDEX_TIMEOUT_SECONDS,
        MAX_REDIRECTS,
        INDEX_LIMIT_BYTES,
        &policy,
    ) {
        Ok((status, body)) if (200..300).contains(&status) => Ok(body),
        Ok(_) => Err(false),
        Err(outcome) => Err(matches!(
            *outcome,
            guard_contracts::EgressOutcomeV1::Error { ref message } if message == "response too large"
        )),
    }
}

/// `report.installed_index`: the listings whose repository a plugin
/// installed here declares.
fn installed_index(index: Vec<Value>, homes: &Map<String, Value>) -> Result<Vec<Value>, String> {
    let result = native_request(&json!({"command": "repositories", "homes": homes}))?;
    Ok(filter_installed(index, result.get("repositories")))
}

/// The filter half of `installed_index`.
pub(in crate::daemon_edge) fn filter_installed(
    index: Vec<Value>,
    repositories: Option<&Value>,
) -> Vec<Value> {
    let keys: BTreeSet<&str> = match repositories {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|item| item.strip_prefix("https://").unwrap_or(item))
            .collect(),
        _ => BTreeSet::new(),
    };
    if keys.is_empty() {
        return Vec::new();
    }
    index
        .into_iter()
        .filter(|entry| {
            entry
                .get("repository")
                .and_then(Value::as_str)
                .map(crate::claude_guard_question::python_lower)
                .is_some_and(|repository| keys.iter().any(|key| repository.contains(key)))
        })
        .collect()
}

/// `report._native_request`, answered in process.
fn native_request(request: &Value) -> Result<Value, String> {
    let text = request.to_string();
    if text.len() > NATIVE_REQUEST_LIMIT_BYTES {
        return Err(
            "The HOL plugin index is too large for this Guard version. Run: hol-guard update"
                .to_owned(),
        );
    }
    let mut response = guard_plugin_telemetry::run_request(text.as_bytes());
    if response.get("ok") == Some(&Value::Bool(true)) {
        if let Some(result @ Value::Object(_)) = response.get_mut("result").map(Value::take) {
            return Ok(result);
        }
    }
    let code = match response.get("error") {
        Some(Value::String(code)) if !code.is_empty() => code.clone(),
        _ => "no result".to_owned(),
    };
    Err(format!(
        "The Guard native runtime refused the report ({code})."
    ))
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_plugin_updates_tests.rs"]
mod tests;
