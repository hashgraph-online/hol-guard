//! `hol-guard telemetry plugins` and `hol-guard plugin updates` on the
//! device: the two public HOL indexes are downloaded under the machine's
//! managed network policy, cut down to the repositories installed here, and
//! matched with the installed plugins by the plugin-telemetry runtime. The
//! weekly install report and its consent state live in
//! [`crate::plugin_telemetry_weekly`].
//!
//! The CLI sends one `plugin-telemetry-host` request; the daemon's weekly
//! worker and its `/v1/plugins/updates` route call the same functions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use guard_command::egress_caller::{policy_get, policy_send};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::managed_policy_load::ManagedPolicySource;
use crate::plugin_telemetry_weekly as weekly;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;

pub(crate) const COMMAND: &str = "plugin-telemetry-host";
pub(crate) const FEATURE: &str = "plugin-telemetry-host-v1";

const INDEX_URL: &str = "https://hol.org/api/guard/plugins/install-telemetry/index";
const RELEASE_INDEX_URL: &str = "https://hol.org/api/guard/plugins/releases/index";
const REPORT_URL: &str = "https://hol.org/api/guard/plugins/install-telemetry";
/// HOL builds the listing index from the whole plugin catalog, which can
/// take about 30 seconds on a server that has not built it yet.
const INDEX_TIMEOUT_SECONDS: f64 = 60.0;
const REPORT_TIMEOUT_SECONDS: f64 = 20.0;
const INDEX_LIMIT_BYTES: u64 = 32 * 1024 * 1024;
const REPORT_REPLY_LIMIT_BYTES: u64 = 64 * 1024;
/// The plugin-telemetry runtime reads at most this much request text.
const NATIVE_REQUEST_LIMIT_BYTES: usize = 6 * 1024 * 1024;
const MAX_REDIRECTS: u32 = 10;
const INDEX_FIELDS: [&str; 4] = ["slug", "repository", "manifestName", "pluginRoot"];

/// What the host needs from HOL. The live implementation downloads under
/// the managed network policy; tests answer from memory.
pub(crate) trait Hol {
    /// The `entries` of one public index, or the message to show.
    fn index(&self, index: Index) -> Result<Vec<Value>, String>;
    /// Sends the weekly report and returns how many entries HOL accepted.
    fn post_report(&self, report: &Value) -> Result<i64, String>;
    /// A runtime directory the user configured through the environment.
    fn configured_dir(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Index {
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

/// HOL reached through the machine's managed network policy.
pub(crate) struct LiveHol;

impl Hol for LiveHol {
    fn index(&self, index: Index) -> Result<Vec<Value>, String> {
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

    fn post_report(&self, report: &Value) -> Result<i64, String> {
        let failed = || "The report could not be sent.".to_owned();
        let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
            .map_err(|_| failed())?;
        let mut headers = request_headers();
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        let (status, _headers, body) = policy_send(
            "POST",
            REPORT_URL,
            headers,
            Some(report.to_string()),
            REPORT_TIMEOUT_SECONDS,
            0,
            REPORT_REPLY_LIMIT_BYTES,
            &policy,
        )
        .map_err(|_| failed())?;
        if !(200..300).contains(&status) {
            return Err(format!("HOL did not accept the report (HTTP {status})."));
        }
        accepted_from(&body).ok_or_else(failed)
    }
}

/// The `accepted` count of HOL's reply; `None` when the reply is not JSON.
/// An empty reply counts as `{}`.
pub(crate) fn accepted_from(body: &[u8]) -> Option<i64> {
    if body.is_empty() {
        return Some(0);
    }
    let payload: Value = serde_json::from_slice(body).ok()?;
    Some(payload.get("accepted").and_then(Value::as_i64).unwrap_or(0))
}

fn request_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("User-Agent".to_owned(), crate::daemon_edge::user_agent()),
        ("Accept".to_owned(), "application/json".to_owned()),
    ])
}

/// One index body. `Err(true)` is a body over the cap; `Err(false)` any
/// other failure, a non-2xx status included.
fn download(url: &str) -> Result<Vec<u8>, bool> {
    let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
        .map_err(|_| false)?;
    match policy_get(
        url,
        request_headers(),
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

/// The object entries of a downloaded index; `Err(parsed)` says whether the
/// body was JSON at all.
pub(crate) fn entries_from(raw: &[u8]) -> Result<Vec<Value>, bool> {
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

/// The agent runtime homes that exist under `home`.
pub(crate) fn runtime_homes(hol: &dyn Hol, home: &Path) -> Map<String, Value> {
    let configured = |name: &str| hol.configured_dir(name);
    let joined = |name: &str| home.join(name).to_string_lossy().into_owned();
    let candidates = [
        (
            "claude",
            configured("CLAUDE_CONFIG_DIR").unwrap_or_else(|| joined(".claude")),
        ),
        (
            "codex",
            configured("CODEX_HOME").unwrap_or_else(|| joined(".codex")),
        ),
        ("gemini", joined(".gemini")),
        ("cursor", joined(".cursor")),
    ];
    candidates
        .into_iter()
        .filter(|(_, path)| Path::new(path).is_dir())
        .map(|(name, path)| (name.to_owned(), Value::String(path)))
        .collect()
}

/// The listing index, each listing keeping only its string index fields.
pub(crate) fn plugin_index(hol: &dyn Hol) -> Result<Vec<Value>, String> {
    Ok(hol
        .index(Index::Plugin)?
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

/// The listings whose repository a plugin installed here declares. The
/// repository list stays on the device.
pub(crate) fn installed_index(
    index: Vec<Value>,
    homes: &Map<String, Value>,
) -> Result<Vec<Value>, String> {
    let result = native_request(&json!({"command": "repositories", "homes": homes}))?;
    Ok(filter_installed(index, result.get("repositories")))
}

/// Keeps the listings whose repository URL contains an installed
/// repository's `host/owner/repo`. The native matcher still decides exactly
/// which listing a plugin belongs to.
pub(crate) fn filter_installed(index: Vec<Value>, repositories: Option<&Value>) -> Vec<Value> {
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

/// One plugin-telemetry runtime request, answered in process.
pub(crate) fn native_request(request: &Value) -> Result<Value, String> {
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

/// `{"updates": [...], "dismissed": n}` for the plugins installed here.
pub(crate) fn check_updates(hol: &dyn Hol, home: &Path, guard_home: &str) -> Result<Value, String> {
    let homes = runtime_homes(hol, home);
    let index = installed_index(plugin_index(hol)?, &homes)?;
    let slugs: BTreeSet<&str> = index
        .iter()
        .filter_map(|entry| entry.get("slug").and_then(Value::as_str))
        .collect();
    let releases: Vec<Value> = hol
        .index(Index::Release)?
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

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Status {
        #[serde(rename = "guardHome")]
        guard_home: String,
    },
    On {
        #[serde(rename = "guardHome")]
        guard_home: String,
    },
    Off {
        #[serde(rename = "guardHome")]
        guard_home: String,
    },
    Send {
        #[serde(rename = "guardHome")]
        guard_home: String,
        home: String,
    },
    DryRun {
        #[serde(rename = "guardHome")]
        guard_home: String,
        home: String,
    },
    Updates {
        #[serde(rename = "guardHome")]
        guard_home: String,
        home: String,
    },
    UpdatesDismiss {
        #[serde(rename = "guardHome")]
        guard_home: String,
        slug: String,
        version: String,
    },
    UpdatesReset {
        #[serde(rename = "guardHome")]
        guard_home: String,
    },
}

/// `{"ok": true, "result": {...}}`, or `{"ok": false, "error": message}`
/// with a message the CLI prints as it is.
pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let answer = serde_json::from_slice::<Request>(bytes)
        .map_err(|_| "The plugin telemetry request was not understood.".to_owned())
        .and_then(|request| respond(&LiveHol, request));
    match answer {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

fn respond(hol: &dyn Hol, request: Request) -> Result<Value, String> {
    match request {
        Request::Status { guard_home } => {
            let state = weekly::read_state(Path::new(&guard_home));
            Ok(json!({"enabled": state.enabled, "lastWeek": state.last_week}))
        }
        Request::On { guard_home } => {
            weekly::turn_on(Path::new(&guard_home))?;
            Ok(json!({"enabled": true}))
        }
        Request::Off { guard_home } => {
            weekly::turn_off(Path::new(&guard_home))?;
            Ok(json!({"enabled": false}))
        }
        Request::Send { guard_home, home } => weekly::send_now(
            hol,
            Path::new(&guard_home),
            Path::new(&home),
            &weekly::current_week(),
        ),
        Request::DryRun { guard_home, home } => weekly::dry_run(
            hol,
            Path::new(&guard_home),
            Path::new(&home),
            &weekly::current_week(),
        ),
        Request::Updates { guard_home, home } => check_updates(hol, Path::new(&home), &guard_home),
        Request::UpdatesDismiss {
            guard_home,
            slug,
            version,
        } => native_request(&json!({
            "command": "updates-dismiss",
            "guardHome": guard_home,
            "slug": slug,
            "version": version,
        })),
        Request::UpdatesReset { guard_home } => native_request(&json!({
            "command": "updates-reset",
            "guardHome": guard_home,
        })),
    }
}

#[cfg(all(test, unix))]
#[path = "plugin_telemetry_host_tests.rs"]
mod tests;
