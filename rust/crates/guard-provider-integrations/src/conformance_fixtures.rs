//! Recorded provider responses and the benign browser corpus, read from the files the conformance
//! kit runs on.
//!
//! A provider's recordings live in `tests/fixtures/provider_integrations/<slug>/recordings.json`:
//!
//! ```json
//! {
//!   "schema": "guard.provider-recordings.v1",
//!   "recordings": [
//!     {"name": "clean", "capability": "browser.origin-reputation", "status": 200,
//!      "body": "{\"verdict\":\"clean\"}", "expect": {"verdict": "ok", "reasonCodes": []}},
//!     {"name": "oversize", "capability": "browser.origin-reputation", "status": 200,
//!      "body": "{\"verdict\":\"clean\"}", "padToBytes": 20000, "expect": {"failure": "oversize"}}
//!   ]
//! }
//! ```
//!
//! `padToBytes` appends spaces after the body, which keeps it valid JSON, so an oversize recording
//! does not need a large file. The corpus is the browser rows of the benign gate
//! (`tests/fixtures/benign_false_positive_gate.json`, `mcp_cases` whose id starts with `browser-`).

use guard_contracts::{ProviderCapabilityV1, ProviderVerdictV1};
use serde::Deserialize;
use serde_json::Value;

use crate::conformance::{RecordedExpectation, RecordedFailure, Recording};
use crate::noise::BaselineDecision;
use crate::parse::parse_strict_bounded;

pub const RECORDINGS_SCHEMA: &str = "guard.provider-recordings.v1";
/// More recordings than any capability set needs: 5 capabilities times 4 verdicts and 5 failures.
pub const MAX_RECORDINGS: usize = 64;
/// Large enough to exceed any `maxResponseBytes` the compiler accepts.
pub const MAX_PAD_BYTES: usize = 1 << 20;

/// The largest `recordings.json` file read. Each response body still has its own cap.
pub const MAX_RECORDINGS_FILE_BYTES: usize = 4 << 20;
const MAX_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureError {
    /// The file is not strict JSON or does not have the expected shape.
    Invalid,
    /// `schema` is not [`RECORDINGS_SCHEMA`].
    Schema,
    /// More than [`MAX_RECORDINGS`] recordings.
    TooMany,
    /// A recording's name is empty, too long, repeated or not lowercase letters, digits and `-`.
    Name(usize),
    /// `padToBytes` is over [`MAX_PAD_BYTES`].
    Pad(usize),
}

impl FixtureError {
    pub fn code(&self) -> String {
        match self {
            Self::Invalid => "recordings_invalid".to_owned(),
            Self::Schema => "recordings_schema".to_owned(),
            Self::TooMany => "recordings_too_many".to_owned(),
            Self::Name(index) => format!("recording_name_invalid at /recordings/{index}"),
            Self::Pad(index) => format!("recording_pad_invalid at /recordings/{index}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV1 {
    schema: String,
    recordings: Vec<EntryV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EntryV1 {
    name: String,
    capability: ProviderCapabilityV1,
    status: u16,
    body: String,
    #[serde(default)]
    pad_to_bytes: Option<usize>,
    expect: ExpectV1,
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ExpectV1 {
    Signal {
        verdict: ProviderVerdictV1,
        #[serde(rename = "reasonCodes", default)]
        reason_codes: Vec<String>,
    },
    Failure {
        failure: FailureV1,
    },
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum FailureV1 {
    Unauthorized,
    RateLimited,
    Status,
    Oversize,
    Malformed,
}

impl From<FailureV1> for RecordedFailure {
    fn from(value: FailureV1) -> Self {
        match value {
            FailureV1::Unauthorized => Self::Unauthorized,
            FailureV1::RateLimited => Self::RateLimited,
            FailureV1::Status => Self::Status,
            FailureV1::Oversize => Self::Oversize,
            FailureV1::Malformed => Self::Malformed,
        }
    }
}

/// One recording with its body owned, as read from the file.
#[derive(Debug, Clone)]
pub struct OwnedRecording {
    pub name: String,
    pub capability: ProviderCapabilityV1,
    pub status: u16,
    pub body: Vec<u8>,
    pub expect: RecordedExpectation,
}

impl OwnedRecording {
    pub fn borrow(&self) -> Recording<'_> {
        Recording {
            name: &self.name,
            capability: self.capability,
            status: self.status,
            body: &self.body,
            expect: self.expect.clone(),
        }
    }
}

fn name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Read a `recordings.json` file.
pub fn parse_recordings(bytes: &[u8]) -> Result<Vec<OwnedRecording>, FixtureError> {
    let value =
        parse_strict_bounded(bytes, MAX_RECORDINGS_FILE_BYTES).ok_or(FixtureError::Invalid)?;
    let file: FileV1 = serde_json::from_value(value).map_err(|_| FixtureError::Invalid)?;
    if file.schema != RECORDINGS_SCHEMA {
        return Err(FixtureError::Schema);
    }
    if file.recordings.len() > MAX_RECORDINGS {
        return Err(FixtureError::TooMany);
    }
    let mut names: Vec<&str> = Vec::with_capacity(file.recordings.len());
    for (index, entry) in file.recordings.iter().enumerate() {
        if !name_is_valid(&entry.name) || names.contains(&entry.name.as_str()) {
            return Err(FixtureError::Name(index));
        }
        names.push(&entry.name);
        if entry.pad_to_bytes.is_some_and(|pad| pad > MAX_PAD_BYTES) {
            return Err(FixtureError::Pad(index));
        }
    }
    Ok(file
        .recordings
        .into_iter()
        .map(|entry| {
            let mut body = entry.body.into_bytes();
            if let Some(pad) = entry.pad_to_bytes {
                body.resize(body.len().max(pad), b' ');
            }
            OwnedRecording {
                name: entry.name,
                capability: entry.capability,
                status: entry.status,
                body,
                expect: match entry.expect {
                    ExpectV1::Signal {
                        verdict,
                        reason_codes,
                    } => RecordedExpectation::Signal {
                        verdict,
                        reason_codes,
                    },
                    ExpectV1::Failure { failure } => RecordedExpectation::Failure(failure.into()),
                },
            }
        })
        .collect())
}

/// Guard's own decision for each browser row of the benign gate. Rows that only set up state are
/// skipped. Returns `None` when the file is not the gate's shape or a browser row has an
/// expectation this reader does not know, so a new kind of row is never silently dropped.
///
/// The gate is Guard's own file and larger than a provider body may be, so it is read with the
/// plain parser rather than [`parse_strict`].
pub fn browser_corpus(gate: &[u8]) -> Option<Vec<BaselineDecision>> {
    let value: Value = serde_json::from_slice(gate).ok()?;
    let cases = value.get("mcp_cases")?.as_array()?;
    let mut corpus = Vec::new();
    for case in cases {
        let id = case.get("id").and_then(Value::as_str)?;
        if !id.starts_with("browser-") {
            continue;
        }
        let decision = match case.get("expect").and_then(Value::as_str)? {
            "setup" => continue,
            "allow" => BaselineDecision::Allow,
            "review" => BaselineDecision::Review,
            "block" => BaselineDecision::Block,
            _ => return None,
        };
        corpus.push(decision);
    }
    Some(corpus)
}

#[cfg(test)]
#[path = "conformance_fixtures_tests.rs"]
mod tests;
