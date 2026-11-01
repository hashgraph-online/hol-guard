//! The bundled tested-version coverage manifest: exact versions, the eligible
//! suites that may back a record, and the validation that turns any defect
//! into `manifest_invalid`.
//!
//! The manifest ships inside the Guard build and is the only coverage
//! authority. There are no ranges: a version that is not listed is not
//! covered, however close it is to a listed one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::CapabilityRow;

const SCHEMA_VERSION: &str = "hol-guard-harness-version-coverage.v1";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_RECORDS_PER_HARNESS: usize = 128;
const MAX_VERSION_TEXT: usize = 64;
const SUPPORTED_PLATFORMS: [&str; 6] = [
    "darwin-arm64",
    "darwin-x86_64",
    "linux-arm64",
    "linux-x86_64",
    "windows-arm64",
    "windows-x86_64",
];
const EVIDENCE_REFERENCE_PREFIX: &str = "https://github.com/hashgraph-online/hol-guard/";
const REMEDIATION_HOSTS: [&str; 3] = ["github.com", "www.npmjs.com", "omp.sh"];
const VERSION_SOURCES: [&str; 2] = ["package-metadata", "unavailable"];
const TOP_KEYS: [&str; 3] = ["schema_version", "revision", "harnesses"];
const HARNESS_KEYS: [&str; 5] = [
    "harness",
    "version_source",
    "limitations",
    "remediation",
    "records",
];
const RECORD_KEYS: [&str; 9] = [
    "harness_version",
    "guard_version",
    "platforms",
    "transport",
    "events",
    "suite",
    "evidence_level",
    "evidence_reference",
    "observed_at",
];

/// A suite whose passing run can support a record, and what it exercises.
/// A record may only claim the events its suite really exercises, at the
/// evidence level that suite really reaches: contract tests against a pinned
/// SDK stay `unit_test`; only a live harness run is `live_block`.
struct EligibleSuite {
    id: &'static str,
    harnesses: &'static [&'static str],
    transport: &'static str,
    events: &'static [&'static str],
    evidence_level: &'static str,
}

const ELIGIBLE_SUITES: [EligibleSuite; 2] = [
    EligibleSuite {
        id: "pi-exact-continuation",
        harnesses: &["omp"],
        transport: "managed_extension",
        events: &["PreToolUse"],
        evidence_level: "unit_test",
    },
    EligibleSuite {
        id: "guard-gauntlet-full-task",
        harnesses: &["omp"],
        transport: "managed_extension",
        events: &["UserPromptSubmit", "PreToolUse", "PostToolUse"],
        evidence_level: "live_block",
    },
];

/// One exact semantic version. A prerelease is never coerced to its stable
/// release and a build identifier stays part of the identity.
pub(super) struct Version {
    pub(super) canonical: String,
    pub(super) prerelease: bool,
}

pub(super) struct Record {
    pub(super) harness_version: String,
    pub(super) guard_version: String,
    pub(super) platforms: Vec<String>,
    pub(super) events: Vec<String>,
    transport: String,
    suite_id: String,
    evidence_level: String,
    evidence_reference: String,
    observed_at: String,
}

impl Record {
    pub(super) fn to_value(&self) -> Value {
        json!({
            "harness_version": self.harness_version,
            "guard_version": self.guard_version,
            "platforms": self.platforms,
            "transport": self.transport,
            "events": self.events,
            // Same shape as the manifest: only passed suites are ever recorded.
            "suite": { "id": self.suite_id, "result": "passed" },
            "evidence_level": self.evidence_level,
            "evidence_reference": self.evidence_reference,
            "observed_at": self.observed_at,
        })
    }
}

pub(super) struct Coverage {
    pub(super) limitations: Vec<String>,
    pub(super) remediation: Vec<Value>,
    pub(super) records: Vec<Record>,
}

pub(super) struct Manifest {
    pub(super) revision: String,
    pub(super) harnesses: BTreeMap<String, Coverage>,
}

/// Parse one exact version string; anything else is `None`.
pub(super) fn parse_version(value: &str) -> Option<Version> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        let identifier = r"[0-9A-Za-z-]+";
        Regex::new(&format!(
            r"^v?(0|[1-9][0-9]{{0,5}})\.(0|[1-9][0-9]{{0,5}})\.(0|[1-9][0-9]{{0,5}})(?:-({identifier}(?:\.{identifier})*))?(?:\+({identifier}(?:\.{identifier})*))?$"
        ))
        .expect("version pattern compiles")
    });
    let text = value.trim();
    if text.is_empty() || text.chars().count() > MAX_VERSION_TEXT {
        return None;
    }
    let captures = pattern.captures(text)?;
    let mut canonical = format!("{}.{}.{}", &captures[1], &captures[2], &captures[3]);
    let prerelease = captures.get(4).map(|found| found.as_str());
    if let Some(prerelease) = prerelease {
        canonical.push('-');
        canonical.push_str(prerelease);
    }
    if let Some(build) = captures.get(5) {
        canonical.push('+');
        canonical.push_str(build.as_str());
    }
    Some(Version {
        canonical,
        prerelease: prerelease.is_some(),
    })
}

/// Load and validate the manifest; any defect is a bounded reason code.
pub(super) fn load(
    path: &Path,
    contracts: &BTreeMap<String, Vec<CapabilityRow>>,
) -> Result<Manifest, &'static str> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| "manifest_missing")?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest_invalid");
    }
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| "manifest_invalid")?;
    parse_manifest(&payload, contracts).ok_or("manifest_invalid")
}

pub(super) fn parse_manifest(
    payload: &Value,
    contracts: &BTreeMap<String, Vec<CapabilityRow>>,
) -> Option<Manifest> {
    let top = keys(payload, &TOP_KEYS)?;
    require(top["schema_version"].as_str() == Some(SCHEMA_VERSION))?;
    let revision = text(&top["revision"], 64)?;
    let entries = top["harnesses"].as_array()?;
    require(entries.len() <= 64)?;
    let mut harnesses = BTreeMap::new();
    for raw in entries {
        let entry = keys(raw, &HARNESS_KEYS)?;
        let harness = text(&entry["harness"], 64)?;
        // Only canonical harness ids carry a contract; an install alias does not.
        let declared = contracts.get(&harness)?;
        require(!harnesses.contains_key(&harness))?;
        let source = entry["version_source"].as_str()?;
        require(VERSION_SOURCES.contains(&source))?;
        let records_raw = entry["records"].as_array()?;
        require(records_raw.len() <= MAX_RECORDS_PER_HARNESS)?;
        require(records_raw.is_empty() || source != "unavailable")?;
        let records = records_raw
            .iter()
            .map(|item| record(&harness, item, declared))
            .collect::<Option<Vec<_>>>()?;
        require(claims_are_distinct(&records))?;
        let coverage = Coverage {
            limitations: text_list(&entry["limitations"], 8)?,
            remediation: remediation(&entry["remediation"])?,
            records,
        };
        harnesses.insert(harness, coverage);
    }
    Some(Manifest {
        revision,
        harnesses,
    })
}

fn record(harness: &str, value: &Value, declared: &[CapabilityRow]) -> Option<Record> {
    let entry = keys(value, &RECORD_KEYS)?;
    let version = parse_version(entry["harness_version"].as_str()?)?;
    let guard_version = parse_version(entry["guard_version"].as_str()?)?;
    let platforms = text_list(&entry["platforms"], SUPPORTED_PLATFORMS.len())?;
    require(
        !platforms.is_empty()
            && platforms
                .iter()
                .all(|platform| SUPPORTED_PLATFORMS.contains(&platform.as_str())),
    )?;
    let events = text_list(&entry["events"], 16)?;
    let transport = text(&entry["transport"], 64)?;
    let suite = keys(&entry["suite"], &["id", "result"])?;
    let suite_id = text(&suite["id"], 64)?;
    let eligible = ELIGIBLE_SUITES
        .iter()
        .find(|eligible| eligible.id == suite_id)?;
    require(eligible.harnesses.contains(&harness))?;
    require(suite["result"].as_str() == Some("passed"))?;
    require(
        transport == eligible.transport
            && !events.is_empty()
            && events
                .iter()
                .all(|event| eligible.events.contains(&event.as_str())),
    )?;
    require(events.iter().all(|event| {
        declared
            .iter()
            .any(|row| row.event == *event && row.transport == transport)
    }))?;
    let evidence_level = text(&entry["evidence_level"], 32)?;
    require(evidence_level == eligible.evidence_level)?;
    let evidence_reference = text(&entry["evidence_reference"], 400)?;
    require(
        evidence_reference.starts_with(EVIDENCE_REFERENCE_PREFIX)
            && !evidence_reference.chars().any(char::is_whitespace),
    )?;
    let observed_at = text(&entry["observed_at"], 40)?;
    require(zoned_timestamp(&observed_at))?;
    Some(Record {
        harness_version: version.canonical,
        guard_version: guard_version.canonical,
        platforms,
        events,
        transport,
        suite_id,
        evidence_level,
        evidence_reference,
        observed_at,
    })
}

/// One (version, Guard build, platform, transport, event) claim per record.
fn claims_are_distinct(records: &[Record]) -> bool {
    let mut seen = BTreeSet::new();
    for record in records {
        for platform in &record.platforms {
            for event in &record.events {
                let claim = (
                    record.harness_version.as_str(),
                    record.guard_version.as_str(),
                    platform.as_str(),
                    record.transport.as_str(),
                    event.as_str(),
                );
                if !seen.insert(claim) {
                    return false;
                }
            }
        }
    }
    true
}

fn remediation(value: &Value) -> Option<Vec<Value>> {
    let items = value.as_array()?;
    require(items.len() <= 8)?;
    items
        .iter()
        .map(|item| {
            let entry = keys(item, &["label", "url"])?;
            let url = text(&entry["url"], 400)?;
            require(reviewed_https_link(&url))?;
            let label = text(&entry["label"], 80)?;
            Some(json!({ "label": label, "url": url }))
        })
        .collect()
}

/// An https link to a reviewed host, with no credentials or port.
fn reviewed_https_link(url: &str) -> bool {
    let Some(scheme_end) = url.find("://") else {
        return false;
    };
    if !url[..scheme_end].eq_ignore_ascii_case("https") {
        return false;
    }
    let rest = &url[scheme_end + 3..];
    let authority = rest
        .split(|ch| matches!(ch, '/' | '?' | '#'))
        .next()
        .unwrap_or_default();
    if authority.contains('@') || authority.contains(':') {
        return false;
    }
    let host = authority.to_ascii_lowercase();
    REMEDIATION_HOSTS.contains(&host.as_str())
}

/// An ISO-8601 date and time that names its offset (`Z` or `+HH:MM`).
fn zoned_timestamp(value: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        Regex::new(
            r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.[0-9]{1,6})?)?(?:Z|[+-]([0-9]{2}):([0-9]{2}))$",
        )
        .expect("timestamp pattern compiles")
    });
    let Some(captures) = pattern.captures(value) else {
        return false;
    };
    let number = |index: usize| -> u32 {
        captures
            .get(index)
            .and_then(|found| found.as_str().parse().ok())
            .unwrap_or(0)
    };
    let (year, month, day) = (number(1), number(2), number(3));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1
        && (1..=month_days).contains(&day)
        && number(4) < 24
        && number(5) < 60
        && number(6) < 60
        && number(7) < 24
        && number(8) < 60
}

fn require(condition: bool) -> Option<()> {
    condition.then_some(())
}

/// An object with exactly `allowed` keys.
fn keys<'a>(value: &'a Value, allowed: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    require(object.len() == allowed.len() && allowed.iter().all(|key| object.contains_key(*key)))?;
    Some(object)
}

fn text(value: &Value, limit: usize) -> Option<String> {
    let text = value.as_str()?;
    require(!text.trim().is_empty() && text.chars().count() <= limit)?;
    Some(text.to_owned())
}

fn text_list(value: &Value, limit: usize) -> Option<Vec<String>> {
    let items = value.as_array()?;
    require(items.len() <= limit)?;
    let texts = items
        .iter()
        .map(|item| text(item, 400))
        .collect::<Option<Vec<_>>>()?;
    let distinct: BTreeSet<&String> = texts.iter().collect();
    require(distinct.len() == texts.len())?;
    Some(texts)
}
