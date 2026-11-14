//! Claim fields of the bundled harness protection contract.
//!
//! Every capability row in `harness-protection-contracts.v1.json` names the
//! surface it covers, what happens when Guard fails on it, and the claim the
//! project publishes for it. A claim that says more than "configured" must
//! name the exact Guard build, harness version and platform it was proven
//! on, a redacted evidence reference, and when that evidence was observed
//! and expires. A claim that says no more than that must carry none of
//! those fields, so a row can never be read two ways.
//!
//! This checks the contract's shape only. It never decides a tool call and
//! nothing here feeds policy, approval, or admission.

use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{json, Value};

const CONTRACT: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/harness-protection-contracts.v1.json"
);
const SCHEMA: &str = "hol-guard.harness-protection-contracts.v1";
const PAYLOAD_SCHEMA: &str = "hol-guard.harness-protection-contract-check.v1";

const SURFACES: [&str; 6] = [
    "foreground",
    "background",
    "editor",
    "cli",
    "cloud-agent",
    "terminal",
];
const FAILURE_BEHAVIORS: [&str; 4] = ["fail_closed", "fail_open", "observe_only", "unsupported"];
const CLAIM_STATES: [&str; 8] = [
    "configured",
    "transport_ready",
    "live_block_proven",
    "live_allow_proven",
    "observe_only",
    "partial",
    "unsupported",
    "stale",
];
/// States that assert something was observed, so they need evidence.
const EVIDENCE_STATES: [&str; 5] = [
    "transport_ready",
    "live_block_proven",
    "live_allow_proven",
    "partial",
    "stale",
];
const MAX_LIMITATION_CHARS: usize = 240;

#[derive(Deserialize)]
struct Document {
    schema: String,
    contracts: Vec<Contract>,
}

#[derive(Deserialize)]
struct Contract {
    harness: String,
    capability_events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    event: String,
    transport: String,
    mode: String,
    #[serde(default)]
    surface: Option<String>,
    #[serde(default)]
    failure_behavior: Option<String>,
    #[serde(default)]
    claim: Option<Claim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    state: String,
    #[serde(default)]
    guard_version: Option<String>,
    #[serde(default)]
    harness_version: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    evidence_reference: Option<String>,
    #[serde(default)]
    observed_at: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    limitations: Vec<String>,
}

impl Claim {
    fn evidence(&self) -> [(&'static str, Option<&str>); 6] {
        [
            ("guard_version", self.guard_version.as_deref()),
            ("harness_version", self.harness_version.as_deref()),
            ("platform", self.platform.as_deref()),
            ("evidence_reference", self.evidence_reference.as_deref()),
            ("observed_at", self.observed_at.as_deref()),
            ("expires_at", self.expires_at.as_deref()),
        ]
    }
}

/// An exact version: no range, wildcard, or `x` placeholder.
fn exact_version(value: &str) -> bool {
    value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        && !value
            .split(['.', '-', '+'])
            .any(|part| part == "x" || part == "X")
}

/// `YYYY-MM-DDTHH:MM:SSZ`. One fixed form keeps text order equal to time order.
fn utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// `os-arch`, lower case, such as `macos-arm64` or `windows-x86_64`.
fn platform(value: &str) -> bool {
    value.split_once('-').is_some_and(|(os, arch)| {
        !os.is_empty()
            && !arch.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
    })
}

/// A run or artifact name, never a local path or a URL with a query.
fn redacted_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && !value.starts_with(['/', '~', '\\', '.'])
        && !value.contains(":\\")
        && !value.contains(['?', '#', ' ', '@'])
        && !value.contains("/Users/")
        && !value.contains("/home/")
}

fn check_evidence(claim: &Claim, problems: &mut Vec<String>) {
    for (field, value) in claim.evidence() {
        if value.is_none_or(str::is_empty) {
            problems.push(format!("{} claim needs {field}", claim.state));
        }
    }
    for (field, value) in [
        ("guard_version", &claim.guard_version),
        ("harness_version", &claim.harness_version),
    ] {
        if let Some(value) = value.as_deref().filter(|value| !exact_version(value)) {
            problems.push(format!("{field} {value:?} is not an exact version"));
        }
    }
    if let Some(value) = claim.platform.as_deref().filter(|value| !platform(value)) {
        problems.push(format!("platform {value:?} is not os-arch"));
    }
    if claim
        .evidence_reference
        .as_deref()
        .is_some_and(|value| !redacted_reference(value))
    {
        problems.push("evidence_reference must be a redacted run or artifact name".to_owned());
    }
    let observed = claim.observed_at.as_deref();
    let expires = claim.expires_at.as_deref();
    for (field, value) in [("observed_at", observed), ("expires_at", expires)] {
        if let Some(value) = value.filter(|value| !utc_timestamp(value)) {
            problems.push(format!("{field} {value:?} is not YYYY-MM-DDTHH:MM:SSZ"));
        }
    }
    if let (Some(observed), Some(expires)) = (observed, expires) {
        if utc_timestamp(observed) && utc_timestamp(expires) && expires <= observed {
            problems.push("expires_at must be after observed_at".to_owned());
        }
    }
}

fn check_claim(claim: &Claim, problems: &mut Vec<String>) {
    if !CLAIM_STATES.contains(&claim.state.as_str()) {
        problems.push(format!("claim state {:?} is not declared", claim.state));
        return;
    }
    if EVIDENCE_STATES.contains(&claim.state.as_str()) {
        check_evidence(claim, problems);
    } else {
        for (field, value) in claim.evidence() {
            if value.is_some() {
                problems.push(format!("{} claim must not carry {field}", claim.state));
            }
        }
    }
    if claim.state == "partial" && claim.limitations.is_empty() {
        problems.push("partial claim must name what it does not cover".to_owned());
    }
    for limitation in &claim.limitations {
        let length = limitation.chars().count();
        if limitation.trim().is_empty() || length > MAX_LIMITATION_CHARS {
            problems.push(format!(
                "each limitation needs 1 to {MAX_LIMITATION_CHARS} characters"
            ));
        }
    }
}

/// Problems with one capability row. Empty when the row is well formed.
fn check_event(event: &Event) -> Vec<String> {
    let mut problems = Vec::new();
    match event.surface.as_deref() {
        None => problems.push("missing surface".to_owned()),
        Some(surface) if !SURFACES.contains(&surface) => {
            problems.push(format!("surface {surface:?} is not declared"));
        }
        Some(_) => {}
    }
    let failure = event.failure_behavior.as_deref();
    match failure {
        None => problems.push("missing failure_behavior".to_owned()),
        Some(value) if !FAILURE_BEHAVIORS.contains(&value) => {
            problems.push(format!("failure_behavior {value:?} is not declared"));
        }
        Some(_) => {}
    }
    let Some(claim) = &event.claim else {
        problems.push("missing claim".to_owned());
        return problems;
    };
    check_claim(claim, &mut problems);
    let no_boundary = matches!(event.transport.as_str(), "none" | "adapter_declared");
    if no_boundary && failure != Some("unsupported") {
        problems.push("a row with no enforceable transport must fail as unsupported".to_owned());
    }
    if event.mode == "observe" && failure != Some("observe_only") {
        problems.push("an observe row must fail as observe_only".to_owned());
    }
    for (behavior, state) in [
        ("unsupported", "unsupported"),
        ("observe_only", "observe_only"),
    ] {
        if (failure == Some(behavior)) != (claim.state == state) {
            problems.push(format!(
                "failure_behavior {behavior} and claim state {state} must go together"
            ));
        }
    }
    problems
}

fn check_document(text: &str) -> (usize, Vec<String>) {
    let document: Document = match serde_json::from_str(text) {
        Ok(document) => document,
        Err(error) => return (0, vec![format!("contract does not parse: {error}")]),
    };
    let mut problems = Vec::new();
    if document.schema != SCHEMA {
        problems.push(format!("unsupported schema {:?}", document.schema));
    }
    let mut rows = 0;
    for contract in &document.contracts {
        for event in &contract.capability_events {
            rows += 1;
            problems.extend(check_event(event).into_iter().map(|problem| {
                format!(
                    "{} {} ({}): {problem}",
                    contract.harness, event.event, event.transport
                )
            }));
        }
    }
    (rows, problems)
}

fn bundled() -> &'static (usize, Vec<String>) {
    static CHECKED: OnceLock<(usize, Vec<String>)> = OnceLock::new();
    CHECKED.get_or_init(|| check_document(CONTRACT))
}

/// The check result for the contract built into this runtime.
pub(crate) fn check_payload() -> Value {
    let (rows, problems) = bundled();
    json!({
        "schema": PAYLOAD_SCHEMA,
        "contract_schema": SCHEMA,
        "valid": problems.is_empty(),
        "rows": rows,
        "problems": problems,
    })
}

#[cfg(test)]
#[path = "harness_protection_contract_tests.rs"]
mod tests;
