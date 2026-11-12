//! Native Cloud actions status for the local dashboard.
//!
//! `GET /v1/cloud-actions/status` shows the pairing, what the last connect
//! said about Cloud actions and the last saved check of Guard Cloud, labelled
//! with its age. This module reads and writes that saved check and composes
//! the projection. Ported from the retired Python `cloud_actions_status.py`
//! (`_read_cache`, `_write_cache`, `_check_dict`, `_site_host`, `_connection`
//! and `cloud_actions_local_status`).
//!
//! Python keeps the pairing read, the one-check-at-a-time lock, the live
//! check of Guard Cloud and the Guard Cloud page address, which depends on the
//! daemon's own environment.

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::guard_store_json::{aware_epoch_micros, civil_date};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const ERR_NOT_SAVED: &str = "cloud_actions_check_not_saved";
const STATUS_SCHEMA: &str = "guard.cloud-actions.local-status.v2";
const CACHE_SCHEMA: &str = "guard.cloud-actions.service-check.v1";
const CACHE_DIRECTORY: &str = "cloud-actions";
const CACHE_FILE: &str = "service-check.json";
const MAX_CACHE_BYTES: u64 = 16 * 1024;
const MAX_MESSAGE_CHARS: usize = 240;
const MICROS_PER_SECOND: i128 = 1_000_000;
const STALE_AFTER_SECONDS: i64 = 5 * 60;
const CHECK_INTERVAL_SECONDS: i64 = 60;
const STALE_AFTER_MICROS: i128 = STALE_AFTER_SECONDS as i128 * MICROS_PER_SECOND;
const CHECK_INTERVAL_MICROS: i128 = CHECK_INTERVAL_SECONDS as i128 * MICROS_PER_SECOND;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    /// What the dashboard may show, from the pairing and the saved check.
    Project {
        pairing: Option<Pairing>,
        now: String,
    },
    /// Save a check of `origin` made at `checked_at` for the connection
    /// `grant_id`.
    Record {
        origin: String,
        #[serde(default)]
        grant_id: Option<String>,
        checked_at: String,
        service: Service,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pairing {
    origin: String,
    /// The connection the pairing belongs to. A check saved for another
    /// connection is not shown, so connecting again starts fresh.
    #[serde(default)]
    grant_id: Option<String>,
    workspace_id: Option<String>,
    /// What the last connect said about Cloud actions: `on`, `off` or `unknown`.
    cloud_actions: String,
    /// Guard Cloud's pages for this pairing, or `None` for a site Guard does
    /// not recognise.
    cloud_base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    state: String,
    message: String,
    http_status: Option<i64>,
}

/// A saved check that names this pairing's Guard Cloud.
#[derive(Debug)]
struct Saved {
    checked: i128,
    checked_at: String,
    next_check_allowed_at: String,
    service: Value,
}

pub(crate) fn dispatch(args: &Value, guard_home: &str) -> KindResult {
    let home = Some(guard_home)
        .filter(|text| !text.contains('\0'))
        .map(Path::new)
        .filter(|home| home.is_absolute())
        .ok_or(ERR_INVALID)?;
    let request: Request = serde_json::from_value(args.clone()).map_err(|_| ERR_INVALID)?;
    match request {
        Request::Project { pairing, now } => {
            let now = aware_epoch_micros(&now).ok_or(ERR_INVALID)?;
            project(home, pairing.as_ref(), now)
        }
        Request::Record {
            origin,
            grant_id,
            checked_at,
            service,
        } => {
            let checked_at = aware_epoch_micros(&checked_at)
                .and_then(iso)
                .ok_or(ERR_INVALID)?;
            let mut entry = json!({
                "schema": CACHE_SCHEMA,
                "origin": origin,
                "checked_at": checked_at,
                "service": check_entry(&service.state, &service.message, service.http_status.map(Value::from)),
            });
            if let Some(grant_id) = grant_id {
                entry["grant_id"] = Value::from(grant_id);
            }
            write_cache(home, &entry).map_err(|_| ERR_NOT_SAVED)?;
            Ok(json!({}))
        }
    }
}

/// `cloud_actions_local_status`, plus how long a new check must wait when
/// the last one is less than a minute old.
fn project(home: &Path, pairing: Option<&Pairing>, now: i128) -> KindResult {
    let saved = pairing.and_then(|pairing| read_cache(home, pairing));
    let elapsed = saved.as_ref().map(|saved| now - saved.checked);
    let retry_after_seconds = elapsed
        .filter(|elapsed| (0..CHECK_INTERVAL_MICROS).contains(elapsed))
        .and_then(|elapsed| {
            i64::try_from((CHECK_INTERVAL_MICROS - elapsed) / MICROS_PER_SECOND).ok()
        })
        .map(|seconds| seconds.max(1));
    let connection = match pairing {
        None => json!({"state": "not_paired", "check": {"state": "not_checked"}}),
        Some(pairing) => {
            let check = match &saved {
                None => json!({"state": "not_checked"}),
                Some(saved) => json!({
                    "checked_at": saved.checked_at,
                    "stale": now - saved.checked > STALE_AFTER_MICROS,
                    "service": saved.service,
                }),
            };
            json!({
                "state": pairing.cloud_actions,
                "workspace": pairing.workspace_id,
                "site": site_host(&pairing.origin),
                "cloud_url": pairing.origin,
                "cloud_base_url": pairing.cloud_base_url,
                "check": check,
            })
        }
    };
    let status = json!({
        "schema": STATUS_SCHEMA,
        "generated_at": iso(now).ok_or(ERR_INVALID)?,
        "stale_after_seconds": STALE_AFTER_SECONDS,
        "check_interval_seconds": CHECK_INTERVAL_SECONDS,
        "next_check_allowed_at": saved.as_ref().map(|saved| saved.next_check_allowed_at.clone()),
        "connection": connection,
        "included_actions": "not_available_yet",
        "accounts": "not_available_yet",
    });
    Ok(json!({"status": status, "retry_after_seconds": retry_after_seconds}))
}

fn cache_path(home: &Path) -> PathBuf {
    home.join(CACHE_DIRECTORY).join(CACHE_FILE)
}

/// `_read_cache`: the saved check, or `None` when it is missing, damaged,
/// too large, or a check of another Guard Cloud or an earlier connection,
/// which says nothing about this pairing.
fn read_cache(home: &Path, pairing: &Pairing) -> Option<Saved> {
    let path = cache_path(home);
    if std::fs::metadata(&path).ok()?.len() > MAX_CACHE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .ok()?
        .take(MAX_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_CACHE_BYTES {
        return None;
    }
    let payload: Value = serde_json::from_slice(&bytes).ok()?;
    let payload = payload.as_object()?;
    if payload.get("schema").and_then(Value::as_str) != Some(CACHE_SCHEMA)
        || payload.get("origin").and_then(Value::as_str) != Some(pairing.origin.as_str())
        || payload.get("grant_id").and_then(Value::as_str) != pairing.grant_id.as_deref()
    {
        return None;
    }
    let checked = aware_epoch_micros(payload.get("checked_at")?.as_str()?)?;
    let service = payload.get("service")?.as_object()?;
    let state = service.get("state")?.as_str()?;
    let message = service.get("message")?.as_str()?;
    let http_status = service
        .get("http_status")
        .filter(|status| status.is_i64() || status.is_u64())
        .cloned();
    Some(Saved {
        checked,
        checked_at: iso(checked)?,
        next_check_allowed_at: iso(checked + CHECK_INTERVAL_MICROS)?,
        service: check_entry(state, message, http_status),
    })
}

/// `_check_dict`: the state code, the message cut to what the page shows,
/// and the HTTP status when there was one.
fn check_entry(state: &str, message: &str, http_status: Option<Value>) -> Value {
    let message: String = message.chars().take(MAX_MESSAGE_CHARS).collect();
    let mut entry = json!({"state": state, "message": message});
    if let Some(http_status) = http_status {
        entry["http_status"] = http_status;
    }
    entry
}

/// `_write_cache`: the check replaces the saved one whole, in a directory only
/// this user can read.
fn write_cache(home: &Path, entry: &Value) -> std::io::Result<()> {
    let directory = home.join(CACHE_DIRECTORY);
    std::fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let text = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    crate::encrypted_secret_store::atomic_write_bytes(&cache_path(home), text.as_bytes(), 0o600)
}

/// `_site_host`: the Guard Cloud host and port, as `urlsplit` reads them, or
/// `None` when the origin names no host or an unreadable port.
fn site_host(origin: &str) -> Option<String> {
    let netloc = origin.split_once("//").map_or("", |(_, rest)| {
        rest.split(['/', '?', '#']).next().unwrap_or_default()
    });
    if netloc.contains('[') != netloc.contains(']') {
        // `urlsplit` raises "Invalid IPv6 URL".
        return None;
    }
    let hostinfo = netloc.rsplit('@').next().unwrap_or_default();
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (hostname, after.split_once(':').map_or("", |(_, port)| port))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    if hostname.is_empty() {
        return None;
    }
    // `SplitResult.hostname` lowercases the address but not an IPv6 zone.
    let hostname = match hostname.split_once('%') {
        Some((address, zone)) => format!("{}%{zone}", address.to_lowercase()),
        None => hostname.to_lowercase(),
    };
    if port.is_empty() {
        return Some(hostname);
    }
    // `SplitResult.port` raises for anything but ASCII digits up to 65535.
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits = port.trim_start_matches('0');
    let number = match digits.len() {
        0 => 0,
        1..=5 => digits.parse::<u32>().ok()?,
        _ => return None,
    };
    (number <= 65_535).then(|| format!("{hostname}:{number}"))
}

/// `_iso`: whole seconds in UTC with a `Z`, or `None` outside the years
/// Python's `datetime` can hold.
fn iso(micros: i128) -> Option<String> {
    let seconds = micros.div_euclid(MICROS_PER_SECOND);
    let days = i64::try_from(seconds.div_euclid(86_400)).ok()?;
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_date(days);
    if !(1..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

#[cfg(test)]
#[path = "cloud_actions_status_tests.rs"]
mod tests;
