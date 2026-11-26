//! The `provider-conformance` command behind `hol-guard integrations conformance` (BP-T180).
//!
//! One request names a provider manifest file. The command finds the provider's recorded responses
//! (`tests/fixtures/provider_integrations/<slug>/recordings.json`) and the benign gate
//! (`tests/fixtures/benign_false_positive_gate.json`) in the checkout that holds the manifest,
//! unless the request names them, and runs the five conformance checks. Nothing is written, no
//! provider is called and no saved key or setting is read.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use guard_provider_integrations::conformance::run_conformance;
use guard_provider_integrations::conformance_fixtures::{browser_corpus, parse_recordings};

pub(crate) const COMMAND: &str = "provider-conformance";

const GATE: &str = "tests/fixtures/benign_false_positive_gate.json";
const RECORDINGS: &str = "tests/fixtures/provider_integrations";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
/// Recordings may pad a body past any `maxResponseBytes`, so they get the padding cap and room.
const MAX_RECORDINGS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GATE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    manifest: String,
    #[serde(default)]
    recordings: Option<String>,
    #[serde(default)]
    gate: Option<String>,
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
}

fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= cap).then_some(bytes)
}

/// The checkout that holds `manifest`: the nearest ancestor with the benign gate in it.
fn checkout_root(manifest: &Path) -> Option<PathBuf> {
    let absolute = fs::canonicalize(manifest).ok()?;
    absolute
        .ancestors()
        .skip(1)
        .find(|directory| directory.join(GATE).is_file())
        .map(Path::to_path_buf)
}

fn provider_slug(manifest: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(manifest).ok()?;
    let slug = value.get("id")?.as_str()?.strip_prefix("provider.")?;
    let safe = !slug.is_empty()
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    safe.then(|| slug.to_owned())
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return refusal("request_invalid", "The request was not understood.");
    };
    let manifest_path = Path::new(&request.manifest);
    let Some(manifest) = read_capped(manifest_path, MAX_MANIFEST_BYTES) else {
        return refusal(
            "manifest_unreadable",
            "The manifest could not be read, or is larger than 256 KiB.",
        );
    };
    let root = checkout_root(manifest_path);
    let gate_path = match (&request.gate, &root) {
        (Some(gate), _) => PathBuf::from(gate),
        (None, Some(root)) => root.join(GATE),
        (None, None) => {
            return refusal(
                "gate_not_found",
                "Run this inside a HOL Guard checkout, or name the benign gate with --gate.",
            )
        }
    };
    let recordings_path = match (&request.recordings, &root, provider_slug(&manifest)) {
        (Some(recordings), _, _) => PathBuf::from(recordings),
        (None, Some(root), Some(slug)) => root.join(RECORDINGS).join(slug).join("recordings.json"),
        (None, _, None) => {
            return refusal(
                "manifest_id_invalid",
                "The manifest id is not provider.<slug>, so its recordings cannot be found. Name them with --recordings.",
            )
        }
        (None, None, Some(_)) => {
            return refusal(
                "recordings_not_found",
                "Run this inside a HOL Guard checkout, or name the recordings with --recordings.",
            )
        }
    };
    let Some(gate) = read_capped(&gate_path, MAX_GATE_BYTES) else {
        return refusal("gate_unreadable", "The benign gate could not be read.");
    };
    let Some(corpus) = browser_corpus(&gate) else {
        return refusal(
            "gate_invalid",
            "The benign gate is not valid or has a browser row this version does not know.",
        );
    };
    let Some(recordings) = read_capped(&recordings_path, MAX_RECORDINGS_BYTES) else {
        return refusal(
            "recordings_unreadable",
            "The recorded responses could not be read. Add them at tests/fixtures/provider_integrations/<slug>/recordings.json.",
        );
    };
    let recordings = match parse_recordings(&recordings) {
        Ok(recordings) => recordings,
        Err(error) => {
            return refusal(
                "recordings_invalid",
                &format!("The recorded responses are not valid: {}.", error.code()),
            )
        }
    };
    let borrowed: Vec<_> = recordings
        .iter()
        .map(|recording| recording.borrow())
        .collect();
    let report = run_conformance(&manifest, &borrowed, &corpus);
    json!({
        "ok": true,
        "provider_id": report.provider_id,
        "passed": report.passed(),
        "corpus_rows": corpus.len(),
        "recordings": recordings.len(),
        "checks": report.checks.iter().map(|check| json!({
            "id": check.id,
            "passed": check.passed(),
            "problems": check.problems,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
#[path = "provider_conformance_command_tests.rs"]
mod tests;
