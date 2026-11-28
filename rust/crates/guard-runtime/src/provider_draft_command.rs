//! The `provider-recordings-draft` command behind `hol-guard extensions generate --provider`
//! (BP-T180).
//!
//! One request carries a provider manifest's text. The answer is the text of a first
//! `recordings.json` for it, drafted and checked by
//! [`guard_provider_integrations::conformance_draft`]. Nothing is read from disk, nothing is
//! written and no provider is called; the CLI writes the file.

use serde::Deserialize;
use serde_json::{json, Value};

use guard_provider_integrations::conformance_draft::{draft_recordings, DraftError};

pub(crate) const COMMAND: &str = "provider-recordings-draft";

const MAX_MANIFEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    manifest: String,
}

fn refusal(code: &str, message: &str, problems: &[String]) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message, "problems": problems}})
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return refusal("request_invalid", "The request was not understood.", &[]);
    };
    if request.manifest.len() > MAX_MANIFEST_BYTES {
        return refusal(
            "manifest_too_large",
            "The manifest is larger than 256 KiB.",
            &[],
        );
    }
    match draft_recordings(request.manifest.as_bytes()) {
        Ok(drafted) => json!({
            "ok": true,
            "provider_id": drafted.provider_id,
            "recordings": drafted.count,
            "recordingsText": drafted.text,
        }),
        Err(DraftError::Unsettled(problems)) => refusal(
            "recordings_draft_unsettled",
            "Drafted responses for this manifest do not read as recorded.",
            &problems,
        ),
        Err(error) => refusal(
            error.code(),
            "No recordings could be drafted for this manifest.",
            &[],
        ),
    }
}

#[cfg(test)]
#[path = "provider_draft_command_tests.rs"]
mod tests;
