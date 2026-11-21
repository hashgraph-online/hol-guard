//! `plugin verify`: HOL's integrity ledger held against what Claude Code
//! installed.
//!
//! The ledger comes from the network, so its shape is checked before anything
//! is read from it, and it must name the listing that was asked for. A
//! difference is only reported; nothing here changes an install.

use serde::Deserialize;
use serde_json::{json, Map, Value};

pub const LEDGER_SCHEMA: &str = "hol.plugin-integrity-ledger.v1";

/// Events that say something about one version's contents; the rest describe
/// packaging and stay on the listing page.
const VERSION_EVENTS: [&str; 4] = [
    "differs",
    "republished",
    "version_withdrawn",
    "pinned_commit_unreachable",
];

/// The version and commit Claude Code recorded for the install.
#[derive(Debug, Default, Deserialize)]
pub struct Installed {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub commit: Option<String>,
}

fn optional_text(item: &Map<String, Value>, key: &str) -> bool {
    matches!(item.get(key), None | Some(Value::Null | Value::String(_)))
}

fn is_text(item: &Map<String, Value>, key: &str) -> bool {
    matches!(item.get(key), Some(Value::String(_)))
}

fn valid_record(item: &Value) -> bool {
    item.as_object().is_some_and(|item| {
        is_text(item, "kind")
            && is_text(item, "channel")
            && optional_text(item, "version")
            && optional_text(item, "commitSha")
    })
}

fn valid_event(item: &Value) -> bool {
    item.as_object().is_some_and(|item| {
        let channels = match item.get("channels") {
            None | Some(Value::Null) => true,
            Some(Value::Array(channels)) => channels.iter().all(Value::is_string),
            Some(_) => false,
        };
        is_text(item, "kind")
            && is_text(item, "sentence")
            && optional_text(item, "version")
            && channels
    })
}

fn well_formed(ledger: &Value) -> Option<(&Vec<Value>, &Vec<Value>)> {
    if ledger.get("schema").and_then(Value::as_str) != Some(LEDGER_SCHEMA) {
        return None;
    }
    let records = ledger.get("records")?.as_array()?;
    let events = ledger.get("events")?.as_array()?;
    (records.iter().all(valid_record) && events.iter().all(valid_event))
        .then_some((records, events))
}

/// Whether the ledger names the listing asked for, or the canonical slug its
/// install spec gave.
fn names_listing(ledger: &Value, slug: &str, spec_slug: &Value) -> bool {
    let Some(named) = ledger.get("slug").and_then(Value::as_str) else {
        return false;
    };
    let named = named.to_lowercase();
    [Some(slug), spec_slug.as_str()]
        .into_iter()
        .flatten()
        .any(|accepted| !accepted.is_empty() && accepted.to_lowercase() == named)
}

/// `{"refused": "shape" | "listing"}` for a ledger that cannot be used, or the
/// installed commit held against the commits HOL recorded for its version:
/// `status` is `matches`, `differs`, `not_recorded`, `no_commit` or
/// `no_version`, with the recorded commits and the version's events.
pub fn check(installed: &Installed, ledger: &Value, slug: &str, spec_slug: &Value) -> Value {
    let Some((records, events)) = well_formed(ledger) else {
        return json!({"refused": "shape"});
    };
    if !names_listing(ledger, slug, spec_slug) {
        return json!({"refused": "listing"});
    }
    let version = installed.version.as_deref();
    let mut commits: Vec<(&str, Vec<&str>)> = Vec::new();
    if let Some(version) = version {
        for item in records.iter().filter_map(Value::as_object) {
            if item.get("kind").and_then(Value::as_str) != Some("git_commit")
                || item.get("version").and_then(Value::as_str) != Some(version)
            {
                continue;
            }
            let Some(sha) = item
                .get("commitSha")
                .and_then(Value::as_str)
                .filter(|sha| !sha.is_empty())
            else {
                continue;
            };
            let at = match commits.iter().position(|(known, _)| *known == sha) {
                Some(at) => at,
                None => {
                    commits.push((sha, Vec::new()));
                    commits.len() - 1
                }
            };
            if let Some(channel) = item
                .get("channel")
                .and_then(Value::as_str)
                .filter(|channel| !commits[at].1.contains(channel))
            {
                commits[at].1.push(channel);
            }
        }
    }
    let status = match installed.commit.as_deref() {
        None => "no_commit",
        Some(_) if version.is_none() => "no_version",
        Some(_) if commits.is_empty() => "not_recorded",
        Some(commit) if commits.iter().any(|(sha, _)| *sha == commit) => "matches",
        Some(_) => "differs",
    };
    let events: Vec<Value> = events
        .iter()
        .filter_map(Value::as_object)
        .filter(|event| {
            let kind = event.get("kind").and_then(Value::as_str);
            let of = event.get("version").and_then(Value::as_str);
            kind.is_some_and(|kind| VERSION_EVENTS.contains(&kind))
                && (of.is_none() || of == version)
        })
        .map(|event| {
            json!({
                "kind": event.get("kind"),
                "version": event.get("version").cloned().unwrap_or(Value::Null),
                "sentence": event.get("sentence"),
            })
        })
        .collect();
    let recorded: Vec<Value> = commits
        .into_iter()
        .map(|(commit, channels)| json!({"commit": commit, "channels": channels}))
        .collect();
    json!({"status": status, "recorded": recorded, "events": events})
}
