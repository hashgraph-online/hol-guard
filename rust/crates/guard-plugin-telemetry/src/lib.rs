//! Opt-in plugin install counts for HOL Guard.
//!
//! Guard downloads the public HOL listing index, and this crate matches the
//! plugins installed under each agent runtime's home against it on the
//! device. Only plugins whose manifest repository is a public HOL listing are
//! reported, so private or unlisted plugin names never leave the machine.
//! Each entry carries a counting key, `HMAC-SHA256(secret, "<week>:<slug>:<runtime>")`,
//! where the secret stays on the device, so the keys differ for every week,
//! listing and runtime. One report carries all of a machine's matched
//! listings, so the keys hide the device, not which listings arrived together.
//!
//! The full index is larger than one native request may be, so Guard first
//! asks for the repositories of the installed plugins (`repositories`), keeps
//! only the index entries for them, and then asks for the report. The
//! repository list stays on the device.
//!
//! `hol-guard telemetry plugins` sends one JSON request on stdin to
//! `hol-guard-runtime plugin-telemetry --stdin` and gets one response back:
//! `{"ok": true, "result": ...}` or `{"ok": false, "error": <code>}`.
//!
//! The same command answers `hol-guard plugin updates` with the `updates`
//! request: it compares installed versions with the public release index on
//! the device and sends nothing.

mod installed;
mod report;
mod updates;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

pub use installed::{discover, InstalledPlugin, RuntimeHomes};
pub use report::{build_report, normalize_repository_url, IndexEntry, ReportEntry};
pub use updates::{
    check_updates, compare_versions, dismiss, parse_release_index, read_dismissals,
    write_dismissals, Dismissal, IndexedRelease, ReleaseIndexEntry, UpdateCheck, UpdatePrompt,
    DISMISSALS_FILE,
};

pub const COMMAND: &str = "plugin-telemetry";
pub const FEATURE: &str = "plugin-telemetry-v1";
pub const UPDATES_FEATURE: &str = "plugin-updates-v1";
pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 200;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Homes {
    #[serde(default)]
    claude: Option<String>,
    #[serde(default)]
    codex: Option<String>,
    #[serde(default)]
    gemini: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Repositories {
        homes: Homes,
    },
    Report {
        homes: Homes,
        index: Vec<IndexEntry>,
        secret: String,
        week: String,
        #[serde(rename = "guardVersion")]
        guard_version: String,
    },
    Updates {
        homes: Homes,
        index: Vec<IndexEntry>,
        releases: Vec<Value>,
        #[serde(rename = "guardHome")]
        guard_home: String,
    },
    #[serde(rename = "updates-dismiss")]
    UpdatesDismiss {
        #[serde(rename = "guardHome")]
        guard_home: String,
        slug: String,
        version: String,
    },
    #[serde(rename = "updates-reset")]
    UpdatesReset {
        #[serde(rename = "guardHome")]
        guard_home: String,
    },
}

fn runtime_homes(homes: Homes) -> RuntimeHomes {
    RuntimeHomes {
        claude: homes.claude.map(PathBuf::from),
        codex: homes.codex.map(PathBuf::from),
        gemini: homes.gemini.map(PathBuf::from),
        cursor: homes.cursor.map(PathBuf::from),
    }
}

/// Runs one request and wraps the outcome in the native response envelope.
pub fn run_request(bytes: &[u8]) -> Value {
    match serde_json::from_slice::<Request>(bytes)
        .map_err(|_| "plugin_telemetry_request_invalid".to_owned())
        .and_then(handle)
    {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

fn handle(request: Request) -> Result<Value, String> {
    match request {
        Request::Repositories { homes } => {
            let repositories: BTreeSet<String> = discover(&runtime_homes(homes))
                .into_iter()
                .filter_map(|plugin| plugin.repository)
                .collect();
            Ok(json!({ "repositories": repositories }))
        }
        Request::Report {
            homes,
            index,
            secret,
            week,
            guard_version,
        } => {
            let secret = decode_secret(&secret)?;
            if !valid_week(&week) {
                return Err("plugin_telemetry_week_invalid".to_owned());
            }
            if !valid_version(&guard_version, 32) {
                return Err("plugin_telemetry_guard_version_invalid".to_owned());
            }
            let installed = discover(&runtime_homes(homes));
            let entries = build_report(&index, &installed, &secret, &week);
            Ok(json!({
                "installed": installed.len(),
                "report": {
                    "schema": SCHEMA_VERSION,
                    "week": week,
                    "guardVersion": guard_version,
                    "entries": entries,
                },
            }))
        }
        Request::Updates {
            homes,
            index,
            releases,
            guard_home,
        } => {
            let installed = discover(&runtime_homes(homes));
            let releases = parse_release_index(&releases);
            let dismissed = read_dismissals(Path::new(&guard_home));
            let check = check_updates(&index, &releases, &installed, &dismissed);
            serde_json::to_value(check).map_err(|_| "plugin_updates_failed".to_owned())
        }
        Request::UpdatesDismiss {
            guard_home,
            slug,
            version,
        } => {
            if slug.is_empty() || slug.len() > 256 || !valid_version(&version, 64) {
                return Err("plugin_updates_dismissal_invalid".to_owned());
            }
            dismiss(Path::new(&guard_home), &slug, &version)?;
            Ok(json!({ "slug": slug, "version": version, "dismissed": true }))
        }
        Request::UpdatesReset { guard_home } => {
            write_dismissals(Path::new(&guard_home), &[])?;
            Ok(json!({ "dismissed": 0 }))
        }
    }
}

fn decode_secret(value: &str) -> Result<Vec<u8>, String> {
    match hex::decode(value) {
        Ok(bytes) if bytes.len() == 32 => Ok(bytes),
        _ => Err("plugin_telemetry_secret_invalid".to_owned()),
    }
}

/// `2026-W43`: four digits, `-W`, a week from 01 to 53.
fn valid_week(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 8 || &bytes[4..6] != b"-W" {
        return false;
    }
    if !bytes[..4].iter().chain(&bytes[6..]).all(u8::is_ascii_digit) {
        return false;
    }
    matches!(value[6..].parse::<u8>(), Ok(1..=53))
}

/// The version shape the portal accepts: starts alphanumeric, then `[0-9A-Za-z.+_-]`.
pub(crate) fn valid_version(value: &str, max: usize) -> bool {
    let mut chars = value.chars();
    value.len() <= max
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weeks_and_versions_match_the_portal_shape() {
        assert!(valid_week("2026-W43"));
        assert!(!valid_week("2026-W00"));
        assert!(!valid_week("2026-W54"));
        assert!(!valid_week("2026-43"));
        assert!(valid_version("1.2.0-beta.1", 64));
        assert!(!valid_version("-1", 64));
        assert!(!valid_version("1 2", 64));
        assert!(!valid_version("", 64));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_secrets() {
        let unknown = br#"{"command":"report","homes":{},"index":[],"secret":"00","week":"2026-W43","guardVersion":"1","hostname":"x"}"#;
        assert_eq!(
            run_request(unknown)["error"],
            "plugin_telemetry_request_invalid"
        );
        let short = br#"{"command":"report","homes":{},"index":[],"secret":"00","week":"2026-W43","guardVersion":"1"}"#;
        assert_eq!(
            run_request(short)["error"],
            "plugin_telemetry_secret_invalid"
        );
    }
}
